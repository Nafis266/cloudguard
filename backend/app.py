import os
import logging
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS

from scanner import AWSScanner
from drift_detector import DriftDetector
from remediation import Remediator
from rewind import SafeRemediator
from rewind_api import create_rewind_blueprint


app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO
)

logger = logging.getLogger(
    "cloudguard"
)


REGION = os.environ.get(
    "AWS_REGION",
    "ap-south-1"
)

BASELINE_PATH = os.environ.get(
    "BASELINE_PATH",
    "../config/baseline.json"
)

MODEL_PATH = os.environ.get(
    "MODEL_PATH",
    "../ml/model.pkl"
)

app.register_blueprint(create_rewind_blueprint(REGION)) 

scanner = AWSScanner(
    region=REGION
)

detector = DriftDetector(
    baseline_path=BASELINE_PATH,
    model_path=MODEL_PATH
)


# Health

@app.route("/api/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "CloudGuard",
        "time": datetime.now(
            timezone.utc
        ).isoformat()
    })


# Scan

@app.route("/api/scan", methods=["GET"])
def scan():

    logger.info(
        "CloudGuard scan started"
    )

    data = scanner.scan_all()

    drifts = detector.analyze(
        data
    )

    logger.info(
        "CloudGuard scan completed: %d drifts",
        len(drifts)
    )

    return jsonify({
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "scan": data,

        "drifts": drifts,

        "drift_count": len(drifts)
    })


# Remediation

@app.route(
    "/api/remediate",
    methods=["POST"]
)
def remediate():

    body = request.get_json(
        silent=True
    )

    if not body:

        return jsonify({
            "error": "JSON body required"
        }), 400

    drift = body.get(
        "drift"
    )

    if not drift:

        return jsonify({
            "error": "drift field required"
        }), 400

    # Default is SAFE.
    dry_run = body.get(
        "dry_run",
        True
    )

    remediator = SafeRemediator(
        region=REGION,
        dry_run=dry_run
    )

    result = remediator.remediate(
        drift
    )

    logger.info(
        "Remediation result: %s",
        result
    )

    return jsonify(result)


# Auto remediation

@app.route(
    "/api/scan-and-remediate",
    methods=["POST"]
)
def scan_and_remediate():

    body = request.get_json(
        silent=True
    ) or {}

    dry_run = body.get(
        "dry_run",
        True
    )

    scan_data = scanner.scan_all()

    drifts = detector.analyze(
        scan_data
    )

    remediator = SafeRemediator(
        region=REGION,
        dry_run=dry_run
    )

    results = []

    for drift in drifts:

        # Only automatically remediate
        # HIGH risk issues.
        if drift.get(
            "risk"
        ) == "HIGH":

            result = remediator.remediate(
                drift
            )

            results.append({
                "drift": drift,
                "remediation": result
            })

    return jsonify({
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "drift_count": len(drifts),

        "drifts": drifts,

        "remediations": results
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
