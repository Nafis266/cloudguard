import boto3
from botocore.exceptions import ClientError


class Remediator:

    def __init__(
        self,
        region=None,
        dry_run=True
    ):

        self.session = boto3.Session(
            region_name=region
        )

        self.s3 = self.session.client("s3")

        self.dry_run = dry_run

    def fix_s3_public_access(
        self,
        bucket_name
    ):

        if self.dry_run:

            return {
                "status": "DRY_RUN",
                "resource": bucket_name,
                "action": (
                    "Enable S3 Block Public Access"
                )
            }

        try:

            self.s3.put_public_access_block(

                Bucket=bucket_name,

                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True
                }
            )

            return {
                "status": "REMEDIATED",
                "resource": bucket_name,
                "action": (
                    "Enabled S3 Block Public Access"
                )
            }

        except ClientError as e:

            return {
                "status": "FAILED",
                "resource": bucket_name,
                "error": str(e)
            }

    def fix_s3_versioning(
        self,
        bucket_name
    ):

        if self.dry_run:

            return {
                "status": "DRY_RUN",
                "resource": bucket_name,
                "action": "Enable S3 versioning"
            }

        try:

            self.s3.put_bucket_versioning(

                Bucket=bucket_name,

                VersioningConfiguration={
                    "Status": "Enabled"
                }
            )

            return {
                "status": "REMEDIATED",
                "resource": bucket_name,
                "action": "Enabled S3 versioning"
            }

        except ClientError as e:

            return {
                "status": "FAILED",
                "resource": bucket_name,
                "error": str(e)
            }

    def remediate(self, drift):

        resource_type = drift.get(
            "resource_type"
        )

        issue = drift.get(
            "issue",
            ""
        )

        resource_id = drift.get(
            "resource_id"
        )

        if resource_type == "s3":

            if "public access" in issue.lower():

                return self.fix_s3_public_access(
                    resource_id
                )

            if "versioning" in issue.lower():

                return self.fix_s3_versioning(
                    resource_id
                )

        return {
            "status": "UNSUPPORTED",
            "resource": resource_id,
            "action": "No remediation available"
        }
