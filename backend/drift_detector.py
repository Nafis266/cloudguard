import json
import os
import joblib


class DriftDetector:

    def __init__(
        self,
        baseline_path="../config/baseline.json",
        model_path="../ml/model.pkl"
    ):

        self.baseline = self._load_baseline(
            baseline_path
        )

        self.model = None

        if os.path.exists(model_path):
            try:
                self.model = joblib.load(
                    model_path
                )
            except Exception:
                self.model = None

    # Load baseline

    def _load_baseline(self, path):

        try:

            with open(path, "r") as file:
                return json.load(file)

        except FileNotFoundError:

            return {
                "s3": {},
                "security_groups": {},
                "ec2": {}
            }

    # ML features

    def _features(
        self,
        resource,
        change_type,
        port=0,
        public_access=0
    ):

        resource_types = {
            "s3": 1,
            "ec2": 2,
            "security_group": 3
        }

        change_types = {
            "none": 0,
            "configuration": 1,
            "security": 2,
            "tag": 3
        }

        return [[
            resource_types.get(
                resource,
                0
            ),

            change_types.get(
                change_type,
                0
            ),

            port,

            public_access
        ]]

    # ML risk

    def calculate_risk(
        self,
        resource,
        change_type,
        port=0,
        public_access=0
    ):

        if self.model is None:
            return {
                "risk": "UNKNOWN",
                "score": 0
            }

        features = self._features(
            resource,
            change_type,
            port,
            public_access
        )

        prediction = self.model.predict(
            features
        )[0]

        score = self.model.decision_function(
            features
        )[0]

        if prediction == -1:

            risk = "HIGH"

        else:

            risk = "LOW"

        return {
            "risk": risk,
            "score": float(score)
        }

    # S3 drift

    def check_s3(self, bucket):

        drifts = []

        baseline = self.baseline.get(
            "s3",
            {}
        )

        if baseline.get(
            "block_public_access"
        ):

            if not bucket.get(
                "block_public_access",
                False
            ):

                risk = self.calculate_risk(
                    "s3",
                    "security",
                    public_access=1
                )

                drifts.append({
                    "resource_type": "s3",
                    "resource_id": bucket["resource_id"],
                    "issue": "S3 public access protection disabled",
                    "expected": True,
                    "actual": False,
                    **risk
                })

        if baseline.get("versioning"):

            if not bucket.get(
                "versioning",
                False
            ):

                risk = self.calculate_risk(
                    "s3",
                    "configuration"
                )

                drifts.append({
                    "resource_type": "s3",
                    "resource_id": bucket["resource_id"],
                    "issue": "S3 versioning disabled",
                    "expected": True,
                    "actual": False,
                    **risk
                })

        if baseline.get("encryption"):

            if not bucket.get(
                "encryption",
                False
            ):

                risk = self.calculate_risk(
                    "s3",
                    "security"
                )

                drifts.append({
                    "resource_type": "s3",
                    "resource_id": bucket["resource_id"],
                    "issue": "S3 encryption disabled",
                    "expected": True,
                    "actual": False,
                    **risk
                })

        return drifts

    # EC2 tag drift

    def check_ec2(self, instance):

        drifts = []

        baseline = self.baseline.get(
            "ec2",
            {}
        )

        required_tags = baseline.get(
            "required_tags",
            []
        )

        actual_tags = instance.get(
            "tags",
            {}
        )

        for required_tag in required_tags:

            if required_tag not in actual_tags:

                risk = self.calculate_risk(
                    "ec2",
                    "tag"
                )

                drifts.append({
                    "resource_type": "ec2",
                    "resource_id": instance[
                        "resource_id"
                    ],
                    "issue": (
                        f"Missing required tag: "
                        f"{required_tag}"
                    ),
                    "expected": required_tag,
                    "actual": None,
                    **risk
                })

        return drifts

    # Full analysis

    def analyze(self, scan):

        all_drifts = []

        for bucket in scan.get(
            "s3",
            []
        ):

            if "error" not in bucket:
                all_drifts.extend(
                    self.check_s3(bucket)
                )

        for group in scan.get(
            "security_groups",
            []
        ):

            if "error" not in group:
                all_drifts.extend(
                    self.check_security_group(
                        group
                    )
                )

        for instance in scan.get(
            "ec2",
            []
        ):

            if "error" not in instance:
                all_drifts.extend(
                    self.check_ec2(
                        instance
                    )
                )

        return all_drifts
