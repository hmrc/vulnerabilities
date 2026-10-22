#!/usr/bin/env python3
"""Loopback-only synthetic JFrog report API for the V2 connector checkpoint."""

import argparse
import io
import itertools
import json
import re
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


DEFAULT_ARTEFACT = "webstore-local/example-service/example-service_1.8.0_0.5.2.tgz"


def report_document(empty, artefact=DEFAULT_ARTEFACT, scenario="populated"):
    document = {
        "generatedDate": "2026-09-11T10:00:00Z",
        "rows": [] if empty else [{
            "cves": [{"cve": "CVE-2026-0001", "cvss_v3_score": 8.1}],
            "cvss3_max_score": 8.1,
            "summary": "Synthetic development finding from the local Xray stub",
            "severity": "High",
            "vulnerable_component": "gav://uk.gov.hmrc:example-lib:2.4.0",
            "component_physical_path": "lib/example-lib-2.4.0.jar",
            "impacted_artifact": artefact.rsplit("/", 1)[-1],
            "impact_path": ["example-service", "example-lib"],
            "path": artefact,
            "fixed_versions": ["2.4.1"],
            "published": "2026-09-01T10:00:00Z",
            "artifact_scan_time": "2026-09-11T10:00:00Z",
            "issue_id": "XRAY-EXAMPLE-0001",
            "package_type": "maven",
            "project_keys": [],
        }],
    }
    if document["rows"]:
        row = document["rows"][0]
        if scenario == "multiple-cves":
            row["cves"].append({"cve": "CVE-2026-0002"})
        elif scenario == "unsupported-id":
            row["cves"][0]["cve"] = "XRAY-UNSUPPORTED"
        elif scenario == "unsupported-package":
            row["package_type"] = "npm"
        elif scenario == "conflicting":
            other = dict(row, vulnerable_component="gav://other:library:1.0")
            document["rows"].append(other)
        elif scenario == "wrong-row-artefact":
            row["path"] = "webstore-local/wrong/other.tgz"
    return document


def handler_for(scenario, artefact=DEFAULT_ARTEFACT):
    reports = {}
    ids = itertools.count(1234)
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def send_body(self, status, body=b"", content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status, body):
            self.send_body(status, json.dumps(body).encode("utf-8"))

        def authenticated(self):
            if (scenario == "unauthorised"
                    or self.headers.get("Authorization") != "Bearer dummy-v2-access-token"):
                self.send_json(401, {"error": "The local stub accepts only its dummy token"})
                return False
            return True

        def do_POST(self):
            if not self.authenticated():
                return
            if self.path != "/xray/api/v1/reports/vulnerabilities":
                self.send_json(404, {"error": "Unknown stub endpoint"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_json(400, {"error": "Invalid Content-Length"})
                return
            if not 0 < length <= 65536:
                self.send_json(400, {"error": "Expected a JSON request of at most 64 KiB"})
                return
            try:
                body = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeDecodeError):
                self.send_json(400, {"error": "Malformed JSON"})
                return
            if not isinstance(body, dict):
                self.send_json(400, {"error": "Expected a JSON object"})
                return
            name = body.get("name")
            filters = body.get("filters")
            requested_artefact = filters.get("impacted_artifact") if isinstance(filters, dict) else None
            if (not isinstance(name, str) or not name.startswith("AppSec-v2-report-")
                    or body.get("resources") != {"repositories": [{"name": "webstore-local"}]}
                    or not isinstance(requested_artefact, str) or not requested_artefact.startswith("*/")
                    or not requested_artefact[2:] or "/" in requested_artefact[2:]
                    or "*" in requested_artefact[2:] or "?" in requested_artefact[2:]):
                self.send_json(400, {"error": "Expected the V2 report name and exact artefact filter"})
                return
            if requested_artefact != "*/" + artefact.rsplit("/", 1)[-1]:
                self.send_json(400, {"error": "Request does not match the configured synthetic artefact"})
                return
            with lock:
                report_id = next(ids)
                reports[report_id] = {"name": name, "polls": 0, "artefact": artefact}
            print(f"Synthetic report created: id={report_id} name={name}", flush=True)
            self.send_json(200, {"report_id": report_id, "status": "pending"})

        def do_GET(self):
            coverage_match = re.fullmatch(r"/__synthetic__/reports/([1-9][0-9]*)/coverage", self.path)
            if coverage_match:
                with lock:
                    report = reports.get(int(coverage_match[1]))
                if report is None or scenario == "missing-coverage":
                    self.send_json(404, {"error": "No synthetic coverage evidence"})
                    return
                document = report_document(scenario == "empty", report["artefact"], scenario)
                self.send_json(200, {
                    "synthetic_contract": "xray-v2-local-v1",
                    "report_id": int(coverage_match[1]),
                    "scanned_artifacts": (["webstore-local/wrong/other.tgz"]
                                          if scenario == "wrong-coverage" else [report["artefact"]]),
                    "number_of_rows": len(document["rows"]),
                })
                return
            if not self.authenticated():
                return
            url = urlsplit(self.path)
            status_match = re.fullmatch(r"/xray/api/v1/reports/([1-9][0-9]*)", url.path)
            export_match = re.fullmatch(r"/xray/api/v1/reports/export/([1-9][0-9]*)", url.path)
            match = status_match or export_match
            report = reports.get(int(match[1])) if match else None
            if report is None:
                self.send_json(404, {"error": "No such synthetic report"})
                return
            if status_match:
                if scenario == "unavailable":
                    self.send_json(503, {"error": "Synthetic upstream outage"})
                    return
                with lock:
                    report["polls"] += 1
                status = ("failed" if scenario == "failed"
                          else "unknown-fixture-status" if scenario == "unknown-status"
                          else "pending" if scenario == "pending" or report["polls"] == 1 else "completed")
                rows = len(report_document(scenario == "empty", report["artefact"], scenario)["rows"])
                self.send_json(200, {
                    "status": status,
                    "number_of_rows": 0 if status != "completed" else rows + (1 if scenario == "wrong-count" else 0),
                    "total_artifacts": 0 if status != "completed" or scenario == "zero-artefacts" else 1,
                })
                return
            if parse_qs(url.query) != {"file_name": [report["name"]], "format": ["json"]}:
                self.send_json(400, {"error": "Expected the report file_name and format=json"})
                return
            if scenario == "malformed-zip":
                self.send_body(200, b"not a ZIP archive", "application/zip")
                return
            text = ("not JSON" if scenario == "malformed-json"
                    else json.dumps(report_document(scenario == "empty", report["artefact"], scenario)))
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("report.json", text)
            self.send_body(200, output.getvalue(), "application/zip")

        def do_DELETE(self):
            if not self.authenticated():
                return
            match = re.fullmatch(r"/xray/api/v1/reports/([1-9][0-9]*)", self.path)
            if scenario == "cleanup-failed":
                self.send_json(503, {"error": "Synthetic cleanup failure"})
                return
            with lock:
                removed = reports.pop(int(match[1]), None) if match else None
            if removed is not None:
                self.send_body(204)
            else:
                self.send_json(404, {"error": "No such synthetic report"})

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18090)
    parser.add_argument("--scenario", choices=[
        "populated", "empty", "unauthorised", "failed", "unavailable",
        "malformed-json", "malformed-zip",
        "multiple-cves", "unsupported-id", "unsupported-package", "conflicting",
        "wrong-row-artefact", "wrong-coverage", "missing-coverage", "wrong-count",
        "zero-artefacts", "pending", "unknown-status", "cleanup-failed",
    ], default="populated")
    parser.add_argument("--artefact", default=DEFAULT_ARTEFACT,
                        help="Exact synthetic fixture path; generation must request its basename")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if (not args.artefact.startswith("webstore-local/")
            or any(part in ("", ".", "..") for part in args.artefact.split("/"))
            or any(c.isspace() or c in "*?#\\" for c in args.artefact)):
        parser.error("--artefact must be an exact webstore-local path")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(args.scenario, args.artefact))
    print(f"SYNTHETIC Xray stub: http://127.0.0.1:{args.port} ({args.scenario})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
