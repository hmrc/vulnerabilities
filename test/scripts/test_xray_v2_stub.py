"""Contract tests for the explicitly synthetic coverage API, using real loopback HTTP."""

import importlib.util
import json
from pathlib import Path
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen


SPEC = importlib.util.spec_from_file_location(
    "xray_v2_stub", Path(__file__).resolve().parents[2] / "scripts" / "xray-v2-stub.py")
STUB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STUB)


class SyntheticCoverageTest(unittest.TestCase):
    def start(self, scenario="populated"):
        server = ThreadingHTTPServer(("127.0.0.1", 0), STUB.handler_for(scenario))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.base = f"http://127.0.0.1:{server.server_port}"

    def call(self, path, method="GET", body=None):
        data = None if body is None else json.dumps(body).encode()
        request = Request(self.base + path, data, method=method, headers={
            "Authorization": "Bearer dummy-v2-access-token", "Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            return response.read()

    def create(self, name="AppSec-v2-report-example-service_1_8_0", basename="example-service_1.8.0_0.5.2.tgz"):
        return json.loads(self.call("/xray/api/v1/reports/vulnerabilities", "POST", {
            "name": name, "resources": {"repositories": [{"name": "webstore-local"}]},
            "filters": {"impacted_artifact": "*/" + basename}}))["report_id"]

    def test_evidence_tracks_exact_fixture_and_unique_report_identity(self):
        self.start()
        first, second = self.create(), self.create()
        self.assertNotEqual(first, second)
        proof = json.loads(self.call(f"/__synthetic__/reports/{first}/coverage"))
        self.assertEqual(proof, {"synthetic_contract": "xray-v2-local-v1", "report_id": first,
                                "scanned_artifacts": [STUB.DEFAULT_ARTEFACT], "number_of_rows": 1})
        self.call(f"/xray/api/v1/reports/{first}", "DELETE")
        with self.assertRaises(HTTPError) as error:
            self.call(f"/__synthetic__/reports/{first}/coverage")
        self.assertEqual(error.exception.code, 404)
        error.exception.close()
        self.assertEqual(json.loads(self.call(f"/__synthetic__/reports/{second}/coverage"))["report_id"], second)

    def test_generation_rejects_a_different_fixture_basename(self):
        self.start()
        with self.assertRaises(HTTPError) as error:
            self.create(basename="another.tgz")
        self.assertEqual(error.exception.code, 400)
        error.exception.close()

    def test_empty_export_retains_positive_verified_artefact_coverage(self):
        self.start("empty")
        report = self.create()
        self.call(f"/xray/api/v1/reports/{report}")
        status = json.loads(self.call(f"/xray/api/v1/reports/{report}"))
        proof = json.loads(self.call(f"/__synthetic__/reports/{report}/coverage"))
        self.assertEqual(status, {"status": "completed", "number_of_rows": 0, "total_artifacts": 1})
        self.assertEqual(proof["scanned_artifacts"], [STUB.DEFAULT_ARTEFACT])
        self.assertEqual(proof["number_of_rows"], 0)

    def test_multiple_cves_count_as_one_raw_row(self):
        self.start("multiple-cves")
        report = self.create()
        proof = json.loads(self.call(f"/__synthetic__/reports/{report}/coverage"))
        self.assertEqual(proof["number_of_rows"], 1)
        self.assertEqual(len(STUB.report_document(False, scenario="multiple-cves")["rows"][0]["cves"]), 2)

    def test_no_evidence_is_available_for_an_uncreated_report(self):
        self.start()
        with self.assertRaises(HTTPError) as error:
            self.call("/__synthetic__/reports/9999/coverage")
        self.assertEqual(error.exception.code, 404)
        error.exception.close()


if __name__ == "__main__":
    unittest.main()
