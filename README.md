# AWS Security Review Tools #

Scripts to assist security testing in AWS environments. Uses a combination of
the AWS APIs to gather data and ansible playbooks to orchestrate some simple
banner grabbing checks.

## inspect_vpc.py ##

Uses the AWS APIs to gather details about a selected VPC. Produces output which
can be used to review security groups and check they allow/deny traffic as
expected.

## ansible/scan_localhost.yaml ##

Runs `nmap` on all hosts, scanning local ports to discover which services are
listening.

## ansible/scan_for_hosts.yaml ##

Runs `nmap` on all hosts scanning a provided list of IP addresses (provided by
`inspect_vpc.py`) attempting to connect to the `listening_ports` which can be
found by running the `ansible/scan_localhost.yaml`.

