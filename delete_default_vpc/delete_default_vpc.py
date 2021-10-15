##########################################################
#
# Python script to delete default vpc
#
# Step1 Delete the internet gateway
# Step2 Delete subnets
# Step3 Delete route tables
# Step4 Delete network access lists
# Step5 Delete security groups
# Step6 Delete the VPC
#
##########################################################

# Imports
import boto3
from botocore.exceptions import ClientError


def delete_igw(ec2, vpc_id):
    # Detach and delete the internet gateway

    args = {
        'Filters': [
             {
                 'Name': 'attachment.vpc-id',
                 'Values': [vpc_id]
             }
        ]
    }

    try:
        igw = ec2.describe_internet_gateways(**args)['InternetGateways']
    except ClientError as e:
        print(e.response['Error']['Message'])

    if igw:
        igw_id = igw[0]['InternetGatewayId']

        print("Deleting internet gateway " + igw_id)

        try:
            ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        except ClientError as e:
            print(e.response['Error']['Message'])

        try:
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        except ClientError as e:
            print(e.response['Error']['Message'])
    else:
        print("No internet gateway found")
    return


def delete_subs(ec2, args):
    # Delete the subnets

    try:
        subs = ec2.describe_subnets(**args)['Subnets']
    except ClientError as e:
        print(e.response['Error']['Message'])

    if subs:
        for sub in subs:
            sub_id = sub['SubnetId']

            print("Deleting subnet " + sub_id)

            try:
                ec2.delete_subnet(SubnetId=sub_id)
            except ClientError as e:
                print(e.response['Error']['Message'])
    else:
        print("No subnets found")
    return


def delete_rtbs(ec2, args):
    # Delete the route tables

    try:
        rtbs = ec2.describe_route_tables(**args)['RouteTables']
    except ClientError as e:
        print(e.response['Error']['Message'])

    if rtbs:
        for rtb in rtbs:
            main = 'false'
            for assoc in rtb['Associations']:
                main = assoc['Main']
            if main == True:
                continue
            rtb_id = rtb['RouteTableId']

            print("Deleting route table " + rtb_id) 

            try:
                ec2.delete_route_table(RouteTableId=rtb_id)
            except ClientError as e:
                print(e.response['Error']['Message'])
    else:
        print("No route tables found")
    return


def delete_acls(ec2, args):
    # Delete the network access lists (NACLs)

    try:
        acls = ec2.describe_network_acls(**args)['NetworkAcls']
    except ClientError as e:
        print(e.response['Error']['Message'])

    if acls:
        for acl in acls:
            default = acl['IsDefault']
            if default is True:
                continue
            acl_id = acl['NetworkAclId']

            print("Deleting access list " + acl_id)

            try:
                ec2.delete_network_acl(NetworkAclId=acl_id)
            except ClientError as e:
                print(e.response['Error']['Message'])
    else:
        print("No acls found")

    return


def delete_sgps(ec2, args):
    # Delete any security groups

    try:
        sgps = ec2.describe_security_groups(**args)['SecurityGroups']
    except ClientError as e:
        print(e.response['Error']['Message'])

    if sgps:
        for sgp in sgps:
            default = sgp['GroupName']
            if default == 'default':
                continue
            sg_id = sgp['GroupId']

            print("Deleting security group " + sg_id)

            try:
                ec2.delete_security_group(GroupId=sg_id)
            except ClientError as e:
                print(e.response['Error']['Message'])
    else:
        print("No sgs found")

    return


def delete_vpc(ec2, vpc_id, region):
    # Delete the VPC

    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as e:
        print(e.response['Error']['Message'])

    print('VPC {} has been deleted from the {} region.'.format(vpc_id, region))

    return


def get_regions(ec2):
    # Return all AWS regions

    regions = []

    try:
        aws_regions = ec2.describe_regions()['Regions']
    except ClientError as e:
        print(e.response['Error']['Message'])

    else:
        for region in aws_regions:
            regions.append(region['RegionName'])

    return regions


def main():
    # Default VPC logic

    # Connect to AWS
    try:
        session = boto3.Session()
        ec2 = session.client('ec2', region_name='us-east-1')
    except ClientError as e:
        print(e.response['Error']['Message'])
        return

    # Get the available regions
    regions = get_regions(ec2)

    # Loop through regions
    for region in regions:

        print("Deleting VPC in region " + region)

        # Create new session for region
        ec2 = session.client('ec2', region_name=region)

        # Get vpc details
        try:
            attribs = ec2.describe_account_attributes(AttributeNames=['default-vpc'])['AccountAttributes']
        except ClientError as e:
            print(e.response['Error']['Message'])
            return

        # Populate VPC ID
        vpc_id = attribs[0]['AttributeValues'][0]['AttributeValue']

        # Check if default VPC exists
        if vpc_id == 'none':
            print('VPC (default) was not found in the {} region.'.format(region))
            continue 
        else:
            print("Deleting vpc " + vpc_id)

        # Check to see if resources exist
        args = {
            'Filters': [
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                }
            ]
         }

        # Get network interfaces to determine if vpc is not empty
        try:
            eni = ec2.describe_network_interfaces(**args)['NetworkInterfaces']
        except ClientError as e:
            print(e.response['Error']['Message'])
            return 

        if eni:
            print('VPC {} has existing resources in the {} region.'.format(vpc_id, region))
            return 

        # Delete VPC and related resources
        delete_igw(ec2, vpc_id)
        delete_subs(ec2, args)
        delete_rtbs(ec2, args)
        delete_acls(ec2, args)
        delete_sgps(ec2, args)
        delete_vpc(ec2, vpc_id, region)

    return


if __name__ == "__main__":

    main()
