"""Flask endpoints for rewind. Register with app.register_blueprint()."""

from flask import Blueprint, jsonify, request

from rewind import SafeRemediator
from rewind_store import RewindStore


def create_rewind_blueprint(region):
    bp = Blueprint("rewind", __name__)

    @bp.route("/api/rewinds")
    def list_rewinds():
        return jsonify(RewindStore().list_records())

    @bp.route("/api/rewind/<rewind_id>", methods=["POST"])
    def rewind(rewind_id):
        body = request.get_json(silent=True) or {}
        hours = body.get("hold_hours", 24)
        remediator = SafeRemediator(region=region, dry_run=False)
        return jsonify(remediator.rewind(rewind_id, hold_hours=hours))

    return bp
