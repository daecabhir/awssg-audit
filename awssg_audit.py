#!/usr/bin/env python3

import argparse
from aws_client import AwsClient

def parse_args():
    parser = argparse.ArgumentParser(description="Audit AWS security groups")
    parser.add_argument("--region", required=True, help="The AWS region to query")
    parser.add_argument("--profile", default="default", help="AWS profile to use for access")
    return parser.parse_args()

def is_open_ipv4_range(ip_range):
    return ip_range.get("CidrIp") == "0.0.0.0/0"

def open_ipv4_ranges_in(ip_ranges):
    return filter(is_open_ipv4_range, ip_ranges)

def has_open_ipv4_ranges(ingress):
    return any(open_ipv4_ranges_in(ingress.get("IpRanges", [])))

def is_open_ipv6_range(ipv6_range):
    return ipv6_range.get("CidrIpv6") == "::/0"

def open_ipv6_ranges_in(ipv6_ranges):
    return filter(is_open_ipv6_range, ipv6_ranges)

def has_open_ipv6_ranges(ingress):
    return any(open_ipv6_ranges_in(ingress.get("Ipv6Ranges", [])))

def has_open_ingress_ranges(ingress):
    return has_open_ipv4_ranges(ingress) or has_open_ipv6_ranges(ingress)

def open_ipv4_ranges_from(ingress):
    return filter(open_ipv4_ranges_in, ingress.get("IpRanges"))

def open_ipv6_ranges_from(ingress):
    return filter(open_ipv6_ranges_in, ingress.get("Ipv6Ranges"))

def with_just_the_open_ranges(ingress):
    ingress["IpRanges"] = [r for r in open_ipv4_ranges_from(ingress)]
    ingress["Ipv6Ranges"] = [r for r in open_ipv6_ranges_from(ingress)]
    return ingress

def ingresses_with_open_ranges_only(ingresses):
    return [with_just_the_open_ranges(i) for i in ingresses if has_open_ingress_ranges(i)]

def open_ingresses_of(group):
    return [i for i in ingresses_with_open_ranges_only(group.ip_permissions)]

def open_ingresses_in(groups):
    return [{ "group_id": g.id, "ingress": i } for g in groups for i in open_ingresses_of(g)]

args = vars(parse_args())
client = AwsClient(**args)
vpcs_by_id = { v.id: v.tags for v in client.all_vpcs() }

security_groups = [g for g in client.all_security_grooups()]
security_groups_by_id = { g.id: g for g in security_groups }
open_ingresses = [i for i in open_ingresses_in(security_groups)]

for i in open_ingresses:
    print(f"Group ID: {i['group_id']}")
    print(f"IPv4: {i['ingress']['IpRanges']}")
    print(f"IPv6: {i['ingress']['Ipv6Ranges']}")
    print("---")
