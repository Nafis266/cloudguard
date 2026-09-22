import os
import json
import logging

from scanner import AWSScanner
from drift_detector import DriftDetector
from remediation import Remediator


logger = logging.getLogger()

logger.setLevel(
    logging.INFO
)


REGION = os.environ.get(
    "AWS_REGION",
    "ap-south-1"
)

BASELINE_PATH = os.environ.get(
    "BASELINE_PATH",
    "/var/task/config/baseline.json"
)

MODEL_PATH = os.environ.get(
    "MODEL_PATH",
    "/var/task/ml/model.pkl"
)

AUTO_REMEDIATE = os.environ.get(
    "AUTO_REMEDIATE",
    "false"
).lower() == "true"


def lambda_handler(
    event,
    context
):

    logger.info(
        "CloudGuard Lambda invoked"
    )

    logger.info(
        "Event: %s",
        json.dumps(event)
    )

    scanner = AWSScanner(
        region=REGION
    )

    detector = DriftDetector(
        baseline_path=BASELINE_PATH,
        model_path=MODEL_PATH
    )

    scan = scanner.scan_all()

    drifts = detector.analyze(
        scan
    )

    remediation_results = []

    if AUTO_REMEDIATE:

        remediator = Remediator(
            region=REGION,
            dry_run=False
        )

        for drift in drifts:

            if drift.get(
                "risk"
            ) == "HIGH":

                result = remediator.remediate(
                    drift
                )

                remediation_results.append(
                    result
                )

    result = {
        "status": "completed",

        "drift_count": len(
            drifts
        ),

        "drifts": drifts,

        "remediations":
            remediation_results
    }

    logger.info(
        "CloudGuard result: %s",
        json.dumps(result)
    )

    return result
