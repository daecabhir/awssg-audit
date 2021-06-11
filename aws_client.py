import boto3

class AwsClient:

    def __init__(self, region, profile):
        self._aws_session = boto3.Session(region_name=region, profile_name=profile)
        self._ec2 = self._aws_session.resource('ec2')

    def all_vpcs(self):
        return self._ec2.vpcs.all()

    def all_security_grooups(self):
        return self._ec2.security_groups.all()
