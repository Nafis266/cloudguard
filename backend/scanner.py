import boto3
from botocore.exceptions import ClientError


class AWSScanner:

    def __init__(self, region=None):
        self.session = boto3.Session(region_name=region)

        self.s3 = self.session.client("s3")
        self.ec2 = self.session.client("ec2")

    # S3

    def scan_s3(self):

        results = []

        try:
            response = self.s3.list_buckets()

            for bucket in response.get("Buckets", []):

                bucket_name = bucket["Name"]

                bucket_data = {
                    "resource_type": "s3",
                    "resource_id": bucket_name,
                    "name": bucket_name,
                    "block_public_access": False,
                    "versioning": False,
                    "encryption": False
                }

                try:
                    public_access = self.s3.get_public_access_block(
                        Bucket=bucket_name
                    )

                    config = public_access["PublicAccessBlockConfiguration"]

                    bucket_data["block_public_access"] = all([
                        config.get("BlockPublicAcls", False),
                        config.get("IgnorePublicAcls", False),
                        config.get("BlockPublicPolicy", False),
                        config.get("RestrictPublicBuckets", False)
                    ])

                except ClientError:
                    bucket_data["block_public_access"] = False

                try:
                    versioning = self.s3.get_bucket_versioning(
                        Bucket=bucket_name
                    )

                    bucket_data["versioning"] = (
                        versioning.get("Status") == "Enabled"
                    )

                except ClientError:
                    bucket_data["versioning"] = False

                try:
                    encryption = self.s3.get_bucket_encryption(
                        Bucket=bucket_name
                    )

                    rules = encryption[
                        "ServerSideEncryptionConfiguration"
                    ].get("Rules", [])

                    bucket_data["encryption"] = len(rules) > 0

                except ClientError:
                    bucket_data["encryption"] = False

                results.append(bucket_data)

        except ClientError as e:

            results.append({
                "resource_type": "s3",
                "error": str(e)
            })

        return results

    # EC2

    def scan_ec2(self):

        results = []

        try:

            response = self.ec2.describe_instances()

            for reservation in response.get(
                "Reservations", []
            ):

                for instance in reservation.get(
                    "Instances", []
                ):

                    instance_id = instance["InstanceId"]

                    tags = {
                        tag["Key"]: tag["Value"]
                        for tag in instance.get("Tags", [])
                    }


                    results.append({
                        "resource_type": "ec2",
                        "resource_id": instance_id,
                        "instance_id": instance_id,
                        "state": instance.get(
                            "State", {}
                        ).get("Name"),
                        "instance_type": instance.get(
                            "InstanceType"
                        ),
                        "tags": tags,
                    })

        except ClientError as e:

            results.append({
                "resource_type": "ec2",
                "error": str(e)
            })

        return results

    def scan_all(self):

        return {
            "s3": self.scan_s3(),
            "ec2": self.scan_ec2(),
        }
