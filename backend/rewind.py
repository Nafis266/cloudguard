"""
Remediation Rewind for CloudGuard.

Before every auto-fix, snapshot the resource's current config.
A fix can then be undone with one call, and a per-resource
"rewind hold" stops CloudGuard from re-fixing it until it expires.
"""

import copy
import uuid

from botocore.exceptions import ClientError

from remediation import Remediator
from rewind_store import RewindStore, now

DEFAULT_HOLD_HOURS = 24
SG_PORTS = {"sg_ssh": 22, "sg_rdp": 3389}


# ---------------------------------------------------------------
# Which fix would CloudGuard run? (mirrors Remediator.remediate)
# ---------------------------------------------------------------

def fix_kind(drift):
    rtype = drift.get("resource_type")
    issue = drift.get("issue", "")

    if rtype == "s3":
        if "public access" in issue.lower():
            return "s3_public_access"
        if "versioning" in issue.lower():
            return "s3_versioning"

    if rtype == "security_group":
        if "SSH" in issue:
            return "sg_ssh"
        if "RDP" in issue:
            return "sg_rdp"

    return None


# ---------------------------------------------------------------
# Snapshot: capture config BEFORE the fix
# ---------------------------------------------------------------

def take_snapshot(kind, resource_id, s3, ec2):
    if kind == "s3_public_access":
        try:
            cfg = s3.get_public_access_block(Bucket=resource_id)
            return {"config": cfg["PublicAccessBlockConfiguration"]}
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return {"config": None}  # there was no block at all
            raise

    if kind == "s3_versioning":
        v = s3.get_bucket_versioning(Bucket=resource_id)
        return {"status": v.get("Status", "")}  # "", Enabled, Suspended

    if kind in SG_PORTS:
        port = SG_PORTS[kind]
        sg = ec2.describe_security_groups(GroupIds=[resource_id])["SecurityGroups"][0]
        rules = []
        for p in sg["IpPermissions"]:
            if (p.get("IpProtocol") == "tcp"
                    and p.get("FromPort") == port
                    and p.get("ToPort") == port):
                for r in p.get("IpRanges", []):
                    if r.get("CidrIp") == "0.0.0.0/0":
                        rule = {"CidrIp": "0.0.0.0/0"}
                        if r.get("Description"):
                            rule["Description"] = r["Description"]
                        rules.append({
                            "IpProtocol": "tcp",
                            "FromPort": port,
                            "ToPort": port,
                            "IpRanges": [rule],
                        })
        return {"rules": rules}

    raise ValueError(f"no snapshot support for {kind}")


# ---------------------------------------------------------------
# Restore: put the config back
# ---------------------------------------------------------------

def restore_state(kind, resource_id, before, s3, ec2):
    """Returns an optional note for the user."""
    if kind == "s3_public_access":
        if before["config"] is None:
            s3.delete_public_access_block(Bucket=resource_id)
        else:
            s3.put_public_access_block(
                Bucket=resource_id,
                PublicAccessBlockConfiguration=before["config"],
            )
        return None

    if kind == "s3_versioning":
        # S3 can never go back to "never versioned".
        # Suspended is the closest state that exists.
        s3.put_bucket_versioning(
            Bucket=resource_id,
            VersioningConfiguration={"Status": "Suspended"},
        )
        return ("S3 cannot undo versioning completely. "
                "Bucket is now Suspended, old versions are kept.")

    if kind in SG_PORTS:
        if before["rules"]:
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=resource_id, IpPermissions=before["rules"])
            except ClientError as e:
                # Rule already exists: treat as already restored
                if e.response["Error"]["Code"] != "InvalidPermission.Duplicate":
                    raise
        return None

    raise ValueError(f"no restore support for {kind}")


# ---------------------------------------------------------------
# Drop-in replacement for Remediator
# ---------------------------------------------------------------

class SafeRemediator(Remediator):

    def __init__(self, region=None, dry_run=True, store=None):
        super().__init__(region=region, dry_run=dry_run)
        self.store = store or RewindStore()

    def remediate(self, drift):
        kind = fix_kind(drift)
        resource_id = drift.get("resource_id")

        # Dry runs and unsupported drifts behave exactly as before
        if kind is None or self.dry_run:
            return super().remediate(drift)

        key = f"{kind}|{resource_id}"

        # 1. Respect a rewind hold
        hold = self.store.active_hold(key)
        if hold:
            return {
                "status": "HELD",
                "resource": resource_id,
                "action": "Skipped: resource was rewound by a human",
                "hold_expires_at": hold["expires_at"],
            }

        # 2. No snapshot, no fix
        try:
            before = take_snapshot(kind, resource_id, self.s3, self.ec2)
        except Exception as e:
            return {
                "status": "SKIPPED",
                "resource": resource_id,
                "error": f"Could not snapshot before fixing: {e}",
            }

        # 3. Apply the normal fix
        result = super().remediate(drift)

        # 4. Record it so it can be rewound
        if result.get("status") == "REMEDIATED":
            rid = "rw-" + uuid.uuid4().hex[:8]
            self.store.add_record({
                "id": rid,
                "time": now().isoformat(),
                "kind": kind,
                "resource_id": resource_id,
                "issue": drift.get("issue"),
                "before": copy.deepcopy(before),
                "status": "applied",
            })
            result["rewind_id"] = rid

        return result

    def rewind(self, rewind_id, hold_hours=DEFAULT_HOLD_HOURS):
        rec = self.store.get_record(rewind_id)
        if not rec:
            return {"status": "NOT_FOUND", "rewind_id": rewind_id}
        if rec["status"] != "applied":
            return {"status": "ALREADY_REWOUND", "rewind_id": rewind_id}

        kind, rid = rec["kind"], rec["resource_id"]

        try:
            note = restore_state(kind, rid, rec["before"], self.s3, self.ec2)
        except ClientError as e:
            return {"status": "FAILED", "rewind_id": rewind_id, "error": str(e)}

        # Hold so CloudGuard doesn't instantly re-fix it
        self.store.add_hold(f"{kind}|{rid}", hold_hours, reason=f"Rewound {rewind_id}")
        self.store.update_record(rewind_id, status="rewound", rewound_at=now().isoformat())

        out = {
            "status": "REWOUND",
            "rewind_id": rewind_id,
            "resource": rid,
            "hold_hours": hold_hours,
            "warning": "Resource is back in its non-compliant state.",
        }
        if note:
            out["note"] = note
        return out
