"""Validation and normalization for Sentinel experiment JSON/JSONL logs."""
from __future__ import annotations

import json
import math
from typing import Any


REQUIRED = {"scenario_key", "configuration", "trial_no", "category"}
CONFIGURATIONS = {"baseline", "content_only", "policy_only", "combined"}
CATEGORIES = {"adversarial", "benign"}
BOOLEAN_FIELDS = {"attack_success", "benign_flagged", "task_success"}
INTEGER_FIELDS = {"trial_no", "unauthorized_proposed", "unauthorized_executed"}
NUMERIC_FIELDS = {"latency_ms", "baseline_latency_ms"}


class LogValidationError(ValueError):
    pass


def _validate_record(record: Any, line_no: int) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise LogValidationError(f"Record {line_no}: expected a JSON object")
    missing = REQUIRED - record.keys()
    if missing:
        raise LogValidationError(f"Record {line_no}: missing fields: {', '.join(sorted(missing))}")
    if not isinstance(record["scenario_key"], str) or not record["scenario_key"].strip():
        raise LogValidationError(f"Record {line_no}: scenario_key must be a non-empty string")
    if record["configuration"] not in CONFIGURATIONS:
        raise LogValidationError(f"Record {line_no}: unsupported configuration")
    if record["category"] not in CATEGORIES:
        raise LogValidationError(f"Record {line_no}: category must be adversarial or benign")
    normalized = dict(record)
    for field in INTEGER_FIELDS:
        value = normalized.get(field, 0 if field != "trial_no" else None)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise LogValidationError(f"Record {line_no}: {field} must be a non-negative integer")
        normalized[field] = value
    if normalized["trial_no"] < 1:
        raise LogValidationError(f"Record {line_no}: trial_no must be at least 1")
    for field in BOOLEAN_FIELDS:
        value = normalized.get(field, False)
        if not isinstance(value, bool):
            raise LogValidationError(f"Record {line_no}: {field} must be boolean")
        normalized[field] = int(value)
    for field in NUMERIC_FIELDS:
        value = normalized.get(field)
        if value is not None:
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value < 0):
                raise LogValidationError(f"Record {line_no}: {field} must be a finite non-negative number or null")
            normalized[field] = float(value)
    normalized.setdefault("unauthorized_proposed", 0)
    normalized.setdefault("unauthorized_executed", 0)
    normalized.setdefault("notes", "")
    if not isinstance(normalized["notes"], str):
        raise LogValidationError(f"Record {line_no}: notes must be a string")
    normalized.setdefault("external_id", "")
    if normalized["unauthorized_executed"] > normalized["unauthorized_proposed"]:
        raise LogValidationError(f"Record {line_no}: executed unauthorized actions exceed proposed actions")
    if not isinstance(normalized.get("external_id"), str):
        raise LogValidationError(f"Record {line_no}: external_id must be a string")
    return normalized


def parse_experiment_logs(raw: str, file_name: str = "upload.json") -> list[dict[str, Any]]:
    """Accept a JSON array/object or JSON Lines; report the offending record."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        records = []
        for index, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(_validate_record(json.loads(line), index))
            except json.JSONDecodeError as exc:
                raise LogValidationError(f"Line {index}: invalid JSON ({exc.msg})") from exc
        if not records:
            raise LogValidationError("The file contains no JSON records")
        return records
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list):
        raise LogValidationError("JSON root must be an object or an array of objects")
    if not parsed:
        raise LogValidationError("The JSON array is empty")
    return [_validate_record(item, index) for index, item in enumerate(parsed, start=1)]
