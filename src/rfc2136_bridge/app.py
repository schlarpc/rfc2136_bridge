"""
RFC 2136 to Route 53 bridge server for solving ACME DNS-01 challenges.

Intentionally limited in capabilities, this server does not validate TSIGs (i.e. no auth)
and can only upsert TXT records used for solving the DNS-01 challenge (i.e. "_acme-challenge.*").

Requires AWS credentials with permission to call the following APIs:
   * `route53:ListHostedZones`
   * `route53:ChangeResourceRecordSets`
"""

import argparse
import collections
import logging
import time
from typing import AsyncGenerator, Optional

import aiobotocore.session
import dns.asyncquery
import dns.asyncresolver
import dns.message
import dns.name
import dns.opcode
import dns.update
import trio
import trio_asyncio
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from trio_asyncio import aio_as_trio as a2t

logger = logging.getLogger(__name__)

session = aiobotocore.session.get_session()


async def list_hosted_zones(
    *, _cache={}, _cache_ttl: int = 300
) -> AsyncGenerator[tuple[str, dns.name.Name], None]:
    """
    Returns all Route 53 hosted zones.

    The results of this function are cached for a short time.
    """
    if "timestamp" not in _cache or _cache["timestamp"] < (time.monotonic() - _cache_ttl):
        async with a2t(session.create_client("route53")) as route53:
            paginator = route53.get_paginator(route53.list_hosted_zones.__name__)
            page_iter = paginator.paginate()
            data = set()
            async for zone in a2t(page_iter.search("HostedZones[?Config.PrivateZone == `false`]")):
                entry = (zone["Id"], dns.name.from_unicode(zone["Name"]))
                data.add(entry)
        _cache.update(
            {
                "timestamp": time.monotonic(),
                "data": frozenset(data),
            }
        )
    for entry in _cache["data"]:
        yield entry


async def get_best_hosted_zone_for_name(name: dns.name.Name) -> str:
    """
    Finds a Route53 hosted zone ID whose name is a superdomain of the argument.

    Determining the actual authoritative zone is not implemented, so if delegated subdomains
    or unused zones exist an exception will be thrown.
    """
    candidates = set()
    async for hosted_zone_id, hosted_zone_name in list_hosted_zones():
        if hosted_zone_name.is_superdomain(name):
            candidates.add(hosted_zone_id)
    if not candidates:
        raise Exception("No candidate zones")
    elif len(candidates) > 1:
        # TODO handle more than one candidate zone by looking at SOA
        raise Exception("More than one candidate zone")
    return next(iter(candidates))


def escape_txt_value(value: bytes) -> str:
    """
    Escapes a single TXT record value as described in the Route 53 documentation:
    https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#TXTFormat
    """
    return "".join(chr(c) if 0x20 < c < 0x7F else f"\\{c:o}" for c in value)


def escape_txt_values(values: tuple[bytes]) -> str:
    """
    Escapes a tuple of TXT record values as described in the Route 53 documentation:
    https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#TXTFormat
    """
    return " ".join(f'"{escape_txt_value(value)}"' for value in values)


async def push_changes_to_route53(zone_changes: dict[str, list[dict[str, str]]]) -> None:
    """
    Push a set of changes to Route 53 hosted zones.
    """
    async with a2t(session.create_client("route53")) as route53:
        change_resource_record_sets = a2t(route53.change_resource_record_sets)
        wait_for_change = a2t(route53.get_waiter("resource_record_sets_changed").wait)
        for hosted_zone_id, changes in zone_changes.items():
            logger.info("Pushing changes to %r: %r", hosted_zone_id, changes)
            response = await change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={
                    "Changes": [
                        {
                            "Action": "UPSERT",
                            "ResourceRecordSet": {
                                "Name": change["name"],
                                "ResourceRecords": [
                                    {
                                        "Value": change["value"],
                                    },
                                ],
                                "Type": "TXT",
                                "TTL": 1,
                            },
                        }
                        for change in changes
                    ],
                },
            )
            # TODO waiting to see if the change succeeded takes a while, and clients are impatient
            # TODO we could spawn this into a nursery just for logging's sake?
            # await wait_for_change(Id=response["ChangeInfo"]["Id"])


async def create_response_for_query(query: dns.message.Message) -> dns.message.Message:
    if not isinstance(query, dns.update.UpdateMessage):
        # for non-update queries, just forward to the default resolver verbatim
        response, _tcp_used = await dns.asyncquery.udp_with_fallback(
            query, dns.asyncresolver.Resolver().nameservers[0]
        )
        return response

    zone_changes = collections.defaultdict(list)
    for rrset in query.update:
        if rrset.deleting is not None:
            # deleting is mildly dangerous, let's just skip it
            continue
        if not rrset.name.labels[:1] == (b"_acme-challenge",):
            # we only care about doing ACME DNS-01 challenges, anything else can go away
            continue

        for rr in rrset:
            if rr.rdtype != RdataType.TXT or rr.rdclass != RdataClass.IN:
                # DNS-01 should only be TXT records
                continue
            hosted_zone_id = await get_best_hosted_zone_for_name(rrset.name)
            zone_changes[hosted_zone_id].append(
                {"name": rrset.name.to_text(), "value": escape_txt_values(rr.strings)}
            )

    await push_changes_to_route53(zone_changes)

    # TODO report failures to the ACME client
    return dns.message.make_response(query)


async def handle_request(sock: trio.socket.socket, data: bytes, client_address) -> None:
    try:
        query = dns.message.from_wire(data)
        response = await create_response_for_query(query)
        await sock.sendto(response.to_wire(), client_address)
    except Exception as ex:
        logger.exception("Failed to handle request: %r", data)


def get_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=53)
    return parser.parse_args(argv)


async def trio_main(argv: Optional[list[str]] = None) -> None:
    args = get_args(argv)
    logging.basicConfig(level=logging.INFO)
    # TODO should we care about TCP requests? ACME update requests are generally small
    sock = trio.socket.socket(type=trio.socket.SOCK_DGRAM)
    await sock.bind((args.host, args.port))
    async with trio.open_nursery() as nursery:
        while True:
            data, client_address = await sock.recvfrom(2 ** 16)
            nursery.start_soon(handle_request, sock, data, client_address)

def main():
    trio_asyncio.run(trio_main)
