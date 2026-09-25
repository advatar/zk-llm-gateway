#!/usr/bin/env python3
"""Build the real Rust bridge and check synthetic Python->Rust->Python vectors.

No skip, mock bridge or caller-set qualification flag. Missing Cargo reports
BLOCKED and exits nonzero. This checks protocol conformance, not payment authority.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def source_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def qualify(sdk: Path, gateway: Path) -> dict:
    report = {
        "schema": "kcf.python-rust-envelope-v2.v1",
        "qualified": False, "status": "BLOCKED", "data": "synthetic",
        "native_cases_executed": 0, "observations": [],
        "payment_finality_verified": False, "hardware_qualified": False,
        "clinical_qualification": False,
    }
    cargo = shutil.which("cargo")
    if cargo is None:
        report["reason"] = "cargo_unavailable"
        return report
    source = sdk / "src"
    required = [source / "zk_llm_gateway_sdk" / name
                for name in ("prepared.py", "prepared_transport.py")]
    bridge_source = gateway / "common/examples/prepared_v2_bridge.rs"
    if not all(p.is_file() for p in [*required, bridge_source, gateway / "Cargo.lock"]):
        report["reason"] = "source_or_lockfile_missing"
        return report
    report["source_sha256"] = {p.name: source_digest(p) for p in [*required, bridge_source]}
    # Refuse an already loaded SDK from another checkout instead of relabeling it.
    if "zk_llm_gateway_sdk" in sys.modules:
        report["reason"] = "sdk_already_imported"
        return report
    sys.path.insert(0, str(source))
    try:
        sdk_types = importlib.import_module("zk_llm_gateway_sdk.prepared")
        transport = importlib.import_module("zk_llm_gateway_sdk.prepared_transport")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    except ImportError:
        report["reason"] = "python_dependencies_missing"
        return report
    if Path(sdk_types.__file__).resolve() != required[0].resolve():
        report["reason"] = "sdk_import_path_mismatch"
        return report
    with tempfile.TemporaryDirectory(prefix="kcf-native-") as directory:
        target = Path(directory)
        command = [cargo, "build", "--locked", "-p", "zk_llm_common", "--example",
                   "prepared_v2_bridge", "--target-dir", str(target)]
        try:
            built = subprocess.run(command, cwd=gateway, capture_output=True, timeout=600)
        except (OSError, subprocess.TimeoutExpired):
            report["reason"] = "native_build_unavailable"
            return report
        if built.returncode != 0:
            report["reason"] = "native_build_failed"
            report["native_build_exit"] = built.returncode
            return report
        executable = target / "debug/examples" / ("prepared_v2_bridge.exe" if os.name == "nt" else "prepared_v2_bridge")
        if not executable.is_file():
            report["reason"] = "native_binary_missing_or_cross_target"
            return report
        report["native_binary_sha256"] = source_digest(executable)
        secret = bytes(range(32))  # PUBLIC SYNTHETIC FIXTURE KEY ONLY
        public = X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        Prepared = sdk_types.PreparedInference
        last = None
        try:
            for cls in sdk_types.CLASSES:
                for temperature in (None, 0, .5, 1, 1.5, 2):
                    prepared = Prepared.prepare(cls, {
                        "model": "synthetic-model", "temperature": temperature,
                        "messages": [{"role": "user", "content": "Ålder, negation, datum — syntetiskt."}],
                        "seed": 7,
                        "response_format": {"type": "json_object"},
                    }, request_id="12345678-1234-4234-9234-123456789abc")
                    authorization = prepared.bind({
                        "commitment_root": prepared.commitment_b64,
                        "nullifier": b64(b"synthetic-replay-id"),
                        "token_class": cls, "proof": b64(b"NOT-REAL-FINALITY"),
                    })
                    envelope, context = transport.seal_request(authorization, public)
                    fixture = {
                        "gateway_secret_key_b64": b64(secret), "envelope": envelope,
                        "expected_request": json.loads(authorization._payload),
                        "expected_commitment_b64": prepared.commitment_b64,
                    }
                    result = subprocess.run([str(executable)], input=sdk_types.encode_json(fixture),
                                            capture_output=True, timeout=15)
                    report["native_cases_executed"] += 1
                    if result.returncode != 0:
                        raise ValueError("native_positive_refused")
                    response = transport.open_response(json.loads(result.stdout), context)
                    if response.get("output") != "synthetic native conformance response":
                        raise ValueError("native_response_mismatch")
                    report["observations"].append({"case": f"{cls}:{temperature}", "kind": "positive", "pass": True})
                    last = fixture
            for field, value in (
                ("v", 1), ("request_id", "00000000-0000-0000-0000-000000000000"),
                ("client_nonce_b64", b64(bytes(32))), ("ciphertext_b64", b64(bytes(16))),
            ):
                fixture = copy.deepcopy(last)
                fixture["envelope"][field] = value
                result = subprocess.run([str(executable)], input=sdk_types.encode_json(fixture),
                                        capture_output=True, timeout=15)
                report["native_cases_executed"] += 1
                # Normal rejection only: a crash/signal is not a passing denial.
                if result.returncode != 1:
                    raise ValueError("negative_case_not_normally_rejected")
                report["observations"].append({"case": field, "kind": "negative", "pass": True})
        except (ValueError, OSError, subprocess.TimeoutExpired):
            report["status"] = "FAILED"
            report["reason"] = "native_conformance_incomplete_or_failed"
            return report
    report["qualified"] = (report["native_cases_executed"] == 34
                           and len(report["observations"]) == 34
                           and all(item["pass"] for item in report["observations"]))
    report["status"] = "PASS" if report["qualified"] else "FAILED"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-dir", type=Path, required=True)
    parser.add_argument("--gateway-dir", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    report = qualify(args.sdk_dir.resolve(), args.gateway_dir.resolve())
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["qualified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
