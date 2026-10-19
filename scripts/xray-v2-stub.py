#!/usr/bin/env python3
"""Loopback-only synthetic JFrog report API for the V2 connector checkpoint."""

import argparse
import io
import json
import re
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def report_document(empty):
    return {
        "generatedDate": "2026-09-11T10:00:00Z",
        "rows": [] if empty else [{
            "cves": [{"cve": "CVE-2026-0001", "cvss_v3_score": 8.1}],
            "cvss3_max_score": 8.1,
            "summary": "Synthetic development finding from the local Xray stub",
            "severity": "High",
            "vulnerable_component": "gav://uk.gov.hmrc:example-lib:2.4.0",
            "component_physical_path": "lib/example-lib-2.4.0.jar",
            "impacted_artifact": "example-service_1.8.0_0.5.2.tgz",
            "impact_path": ["example-service", "example-lib"],
            "path": "webstore-local/example-service/example-service_1.8.0_0.5.2.tgz",
            "fixed_versions": ["2.4.1"],
            "published": "2026-09-01T10:00:00Z",
            "artifact_scan_time": "2026-09-11T10:00:00Z",
            "issue_id": "XRAY-EXAMPLE-0001",
            "package_type": "maven",
            "project_keys": [],
        }],
    }


def handler_for(scenario):
    reports = {}

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
            artefact = filters.get("impacted_artifact") if isinstance(filters, dict) else None
            if (not isinstance(name, str) or not name.startswith("AppSec-v2-report-")
                    or body.get("resources") != {"repositories": [{"name": "webstore-local"}]}
                    or not isinstance(artefact, str) or not artefact.startswith("*/")
                    or not artefact[2:] or "/" in artefact[2:]
                    or "*" in artefact[2:] or "?" in artefact[2:]):
                self.send_json(400, {"error": "Expected the V2 report name and exact artefact filter"})
                return
            reports[1234] = {"name": name, "polls": 0}
            print("Synthetic report created: " + name, flush=True)
            self.send_json(200, {"report_id": 1234, "status": "pending"})

        def do_GET(self):
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
                report["polls"] += 1
                status = ("failed" if scenario == "failed"
                          else "pending" if report["polls"] == 1 else "completed")
                self.send_json(200, {
                    "status": status,
                    "number_of_rows": 0 if scenario == "empty" or status != "completed" else 1,
                    "total_artifacts": 0 if status != "completed" else 1,
                })
                return
            if parse_qs(url.query) != {"file_name": [report["name"]], "format": ["json"]}:
                self.send_json(400, {"error": "Expected the report file_name and format=json"})
                return
            if scenario == "malformed-zip":
                self.send_body(200, b"not a ZIP archive", "application/zip")
                return
            text = ("not JSON" if scenario == "malformed-json"
                    else json.dumps(report_document(scenario == "empty")))
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("report.json", text)
            self.send_body(200, output.getvalue(), "application/zip")

        def do_DELETE(self):
            if not self.authenticated():
                return
            match = re.fullmatch(r"/xray/api/v1/reports/([1-9][0-9]*)", self.path)
            if match and reports.pop(int(match[1]), None) is not None:
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
    ], default="populated")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(args.scenario))
    print(f"SYNTHETIC Xray stub: http://127.0.0.1:{args.port} ({args.scenario})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
