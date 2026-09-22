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
        self.ec2 = self.session.client("ec2")

        self.dry_run = dry_run

    # ---------------------------------------------------------
    # S3 public access
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # S3 versioning
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # Security group SSH
    # ---------------------------------------------------------

    def fix_ssh_public_access(
        self,
        security_group_id
    ):

        if self.dry_run:

            return {
                "status": "DRY_RUN",
                "resource": security_group_id,
                "action": (
                    "Remove public SSH ingress"
                )
            }

        try:

            self.ec2.revoke_security_group_ingress(

                GroupId=security_group_id,

                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [
                            {
                                "CidrIp": "0.0.0.0/0"
                            }
                        ]
                    }
                ]
            )

            return {
                "status": "REMEDIATED",
                "resource": security_group_id,
                "action": (
                    "Removed public SSH ingress"
                )
            }

        except ClientError as e:

            return {
                "status": "FAILED",
                "resource": security_group_id,
                "error": str(e)
            }

    # ---------------------------------------------------------
    # Security group RDP
    # ---------------------------------------------------------

    def fix_rdp_public_access(
        self,
        security_group_id
    ):

        if self.dry_run:

            return {
                "status": "DRY_RUN",
                "resource": security_group_id,
                "action": (
                    "Remove public RDP ingress"
                )
            }

        try:

            self.ec2.revoke_security_group_ingress(

                GroupId=security_group_id,

                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3389,
                        "ToPort": 3389,
                        "IpRanges": [
                            {
                                "CidrIp": "0.0.0.0/0"
                            }
                        ]
                    }
                ]
            )

            return {
                "status": "REMEDIATED",
                "resource": security_group_id,
                "action": (
                    "Removed public RDP ingress"
                )
            }

        except ClientError as e:

            return {
                "status": "FAILED",
                "resource": security_group_id,
                "error": str(e)
            }

    # ---------------------------------------------------------
    # Dispatch remediation
    # ---------------------------------------------------------

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

        if resource_type == "security_group":

            if "SSH" in issue:

                return self.fix_ssh_public_access(
                    resource_id
                )

            if "RDP" in issue:

                return self.fix_rdp_public_access(
                    resource_id
                )

        return {
            "status": "UNSUPPORTED",
            "resource": resource_id,
            "action": "No remediation available"
        }
