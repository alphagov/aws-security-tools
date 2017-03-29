import click
import json
import boto3
import pprint
import configparser
from collections import defaultdict
from itertools import groupby

def get_security_groups(ec2):
    sgs = ec2.describe_security_groups()
    groups = {}
    name_map = {}
    for sgid, sg in groupby(sgs['SecurityGroups'], lambda g: g['GroupId']):
        groups[sgid] = next(sg)
        name_map[sgid] = groups[sgid]['GroupName']
    for sgid, sg in groups.items():
        groups[sgid] = tidy_security_group(sg, name_map)
    return groups

def tidy_security_group(sg, name_map):
    minimal_sg = {
        'group_id': sg['GroupId'],
        'group_name': sg['GroupName'],
        'ingress_rules': [],
        'egress_rules': [],
    }
    for rule in sg['IpPermissions']:
        minimal_sg['ingress_rules'].append(
            "Allow {protocol} traffic from {ranges} to ports {from_port}-{to_port}".format(
                protocol = rule['IpProtocol'],
                ranges = tidy_ranges(rule, name_map),
                from_port = rule.get('FromPort', -1),
                to_port = rule.get('ToPort', -1),
            )
        )
    for rule in sg['IpPermissionsEgress']:
        protocol = 'all' if rule['IpProtocol'] else rule['IpProtocol']
        minimal_sg['egress_rules'].append(
            "Allow {protocol} traffic to {ranges} on ports {from_port}-{to_port}".format(
                protocol = protocol,
                ranges = tidy_ranges(rule, name_map),
                from_port = rule.get('FromPort', 'any'),
                to_port = rule.get('ToPort', 'any'),
            )
        )
    return minimal_sg

def tidy_ranges(rule, name_map):
    ranges = 'nowhere'
    if rule['IpRanges']:
        ranges = [r['CidrIp'] for r in rule['IpRanges']]
    elif rule['UserIdGroupPairs']:
        ranges = [(r['GroupId'], name_map[r['GroupId']]) for r in rule['UserIdGroupPairs']]
    return ranges

def get_annotated_instances(ec2, vpc_id, security_groups):
    result = ec2.describe_instances(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    instances = []
    for reservation in result['Reservations']:
        for instance in reservation['Instances']:
            minimal_instance = {
                'public_ip': instance.get('PublicIpAddress', None),
                'private_ip': instance['PrivateIpAddress'],
                'instance_id': instance['InstanceId'],
                'tags': dict([(tag['Key'], tag['Value']) for tag in instance['Tags']]),
                'security_groups': [],
            }
            for security_group in instance['SecurityGroups']:
                minimal_instance['security_groups'].append(security_groups[security_group['GroupId']])
            instances.append(minimal_instance)
    return instances

def pick_vpc(ec2):
    vpcs = ec2.describe_vpcs()
    for vpc in vpcs['Vpcs']:
        pprint.pprint(vpc)
        yesno = input("Dump security groups for this VPC into {}.json? (y/n) ".format(vpc['VpcId']))
        if yesno.lower() in ['y', 'yes']:
            return vpc['VpcId']

def output_instances_for_ansible(env, filename, instances, filter_tag):
    config = configparser.ConfigParser(allow_no_value=True)
    for instance in instances:
        name = "{}.{}".format(instance['tags']['Name'], env)
        if instance['tags'][filter_tag] not in config.sections():
            config[instance['tags'][filter_tag]] = {name: None}
        else:
            config[instance['tags'][filter_tag]][name] = None
    with open(filename, 'w') as fp:
        config.write(fp)

def output_list_of_ips(filename, instances):
    ips = []
    with open(filename, 'w') as ip_list:
        for instance in instances:
            ips.append("{}\n{}\n".format(instance['private_ip'], instance['public_ip']))
        ip_list.writelines(ips)

@click.command()
@click.option('--env', default='dev')
@click.option('--filter-tag', default='Tier')
def inspect_vpc(env, filter_tag):
    ec2 = boto3.client('ec2')

    vpc = pick_vpc(ec2)
    if vpc:
        sgs = get_security_groups(ec2)
        instances = get_annotated_instances(ec2, vpc, sgs)
        with open("{}.json".format(vpc), 'w') as fp:
            json.dump(instances, fp, sort_keys=True, indent=4, separators=(',', ': '))

        inventory_filename = "{}.ini".format(vpc)
        yesno = input("Dump ansible inventory for this VPC into {}? (y/n) ".format(inventory_filename))
        if yesno.lower() in ['y', 'yes']:
            output_instances_for_ansible(env, inventory_filename, instances, filter_tag)
        ip_list_filename = "{}.ips".format(vpc)
        yesno = input("Dump ips for this VPC into {}? (y/n) ".format(ip_list_filename))
        if yesno.lower() in ['y', 'yes']:
            output_list_of_ips(ip_list_filename, instances)

if __name__=='__main__':
    inspect_vpc()
