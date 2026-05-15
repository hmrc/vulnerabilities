package uk.gov.hmrc.vulnerabilities.connector

object XRayTestData {

  lazy val vulnerabilityEntryV1: String =
    """{
      |  "cves" : [ {
      |    "cve" : "CVE-1",
      |    "cvss_v3_score" : 8,
      |    "cvss_v3_vector" : "test"
      |  } ],
      |  "cvss3_max_score" : 8,
      |  "summary" : "This is an exploit",
      |  "severity" : "High",
      |  "severity_source" : "Source",
      |  "vulnerable_component" : "gav://com.testxml.test.core:test-bind:1.5.9",
      |  "component_physical_path" : "service1-1.0.4/some/physical/path",
      |  "impacted_artifact" : "fooBar",
      |  "impact_path" : [ "hello", "world" ],
      |  "path" : "test/slugs/service1/service1_1.0.4_0.0.1.tgz",
      |  "fixed_versions" : [ "1.6.0" ],
      |  "published" : "2022-12-01T00:00:00Z",
      |  "artifact_scan_time" : "2022-12-13T00:00:00Z",
      |  "issue_id" : "XRAY-000003",
      |  "package_type" : "maven",
      |  "provider" : "test",
      |  "description" : "This is an exploit description",
      |  "references" : [ "foo.com", "bar.net" ],
      |  "project_keys" : [ ]
      |}
      |""".stripMargin

  lazy val vulnerabilityEntryV1_X_missingFields: String =
    """{
      |  "cves" : [ {
      |    "cve" : "CVE-1",
      |    "cvss_v3_score" : 8,
      |    "cvss_v3_vector" : "test"
      |  } ],
      |  "cvss3_max_score" : 8,
      |  "summary" : "This is an exploit",
      |  "severity" : "High",
      |  "vulnerable_component" : "gav://com.testxml.test.core:test-bind:1.5.9",
      |  "component_physical_path" : "service1-1.0.4/some/physical/path",
      |  "impacted_artifact" : "fooBar",
      |  "impact_path" : [ "hello", "world" ],
      |  "path" : "test/slugs/service1/service1_1.0.4_0.0.1.tgz",
      |  "fixed_versions" : [ "1.6.0" ],
      |  "published" : "2022-12-01T00:00:00Z",
      |  "artifact_scan_time" : "2022-12-13T00:00:00Z",
      |  "issue_id" : "XRAY-000003",
      |  "package_type" : "maven",
      |  "project_keys" : [ ]
      |}
      |""".stripMargin

  lazy val vuln1JsonV1: String =
    """{
      |  "cves" : [ {
      |    "cve" : "CVE-2021-99999",
      |    "cvss_v3_score" : 7,
      |    "cvss_v3_vector" : "test1"
      |  } ],
      |  "cvss3_max_score" : 7,
      |  "summary" : "This is a lower severity exploit",
      |  "severity" : "High",
      |  "severity_source" : "Source",
      |  "vulnerable_component" : "gav://com.testxml.test.core:test-bind:1.6.8",
      |  "component_physical_path" : "service2-3.0.4/some/physical/path",
      |  "impacted_artifact" : "fooBar",
      |  "impact_path" : [ "hello", "world" ],
      |  "path" : "test/slugs/service2/service2_3.0.4_0.0.1.tgz",
      |  "fixed_versions" : [ "1.6.9" ],
      |  "published" : "2026-05-15T00:00:00Z",
      |  "artifact_scan_time" : "2026-05-15T00:00:00Z",
      |  "issue_id" : "XRAY-000002",
      |  "package_type" : "maven",
      |  "provider" : "test1",
      |  "description" : "This is the first exploit",
      |  "references" : [ "foo.com", "bar.net" ],
      |  "project_keys" : [ ],
      |  "importedBy" : {
      |    "group" : "some-group",
      |    "artefact" : "some-artefact",
      |    "version" : "0.2.0"
      |  }
      |}
      |""".stripMargin

  lazy val vuln2JsonV1: String =
    """
      |{
      |  "cves" : [ {
      |    "cve" : "CVE-2022-12345",
      |    "cvss_v3_score" : 8,
      |    "cvss_v3_vector" : "test2"
      |  } ],
      |  "cvss3_max_score" : 8,
      |  "summary" : "This is a higher severity exploit",
      |  "severity" : "High",
      |  "severity_source" : "Source",
      |  "vulnerable_component" : "gav://com.testxml.test.core:test-bind:1.5.9",
      |  "component_physical_path" : "service2-3.0.4/some/physical/path",
      |  "impacted_artifact" : "fooBar",
      |  "impact_path" : [ "hello", "world" ],
      |  "path" : "test/slugs/service2/service2_3.0.4_0.0.1.tgz",
      |  "fixed_versions" : [ "1.6.0" ],
      |  "published" : "2026-05-15T00:00:00Z",
      |  "artifact_scan_time" : "2026-05-15T00:00:00Z",
      |  "issue_id" : "XRAY-000003",
      |  "package_type" : "maven",
      |  "provider" : "test2",
      |  "description" : "This is the second exploit",
      |  "references" : [ "buzz.com", "fizz.net" ],
      |  "project_keys" : [ ],
      |  "importedBy" : {
      |    "group" : "some-group",
      |    "artefact" : "some-artefact",
      |    "version" : "0.1.0"
      |  }
      |}
      |""".stripMargin


  lazy val vuln1JsonV1xMissingFields: String =
    """{
      |  "cves" : [ {
      |    "cve" : "CVE-2021-99999",
      |    "cvss_v3_score" : 7,
      |    "cvss_v3_vector" : "test1"
      |  } ],
      |  "cvss3_max_score" : 7,
      |  "summary" : "This is a lower severity exploit",
      |  "severity" : "High",
      |  "vulnerable_component" : "gav://com.testxml.test.core:test-bind:1.6.8",
      |  "component_physical_path" : "service2-3.0.4/some/physical/path",
      |  "impacted_artifact" : "fooBar",
      |  "impact_path" : [ "hello", "world" ],
      |  "path" : "test/slugs/service2/service2_3.0.4_0.0.1.tgz",
      |  "fixed_versions" : [ "1.6.9" ],
      |  "published" : "2026-05-15T00:00:00Z",
      |  "artifact_scan_time" : "2026-05-15T00:00:00Z",
      |  "issue_id" : "XRAY-000002",
      |  "package_type" : "maven",
      |  "project_keys" : [ ],
      |  "importedBy" : {
      |    "group" : "some-group",
      |    "artefact" : "some-artefact",
      |    "version" : "0.2.0"
      |  }
      |}
      |""".stripMargin

  lazy val vuln2JsonV1xMissingFields: String =
    """
      |{
      |  "cves" : [ {
      |    "cve" : "CVE-2022-12345",
      |    "cvss_v3_score" : 8,
      |    "cvss_v3_vector" : "test2"
      |  } ],
      |  "cvss3_max_score" : 8,
      |  "summary" : "This is a higher severity exploit",
      |  "severity" : "High",
      |  "vulnerable_component" : "gav://com.testxml.test.core:test-bind:1.5.9",
      |  "component_physical_path" : "service2-3.0.4/some/physical/path",
      |  "impacted_artifact" : "fooBar",
      |  "impact_path" : [ "hello", "world" ],
      |  "path" : "test/slugs/service2/service2_3.0.4_0.0.1.tgz",
      |  "fixed_versions" : [ "1.6.0" ],
      |  "published" : "2026-05-15T00:00:00Z",
      |  "artifact_scan_time" : "2026-05-15T00:00:00Z",
      |  "issue_id" : "XRAY-000003",
      |  "package_type" : "maven",
      |  "project_keys" : [ ],
      |  "importedBy" : {
      |    "group" : "some-group",
      |    "artefact" : "some-artefact",
      |    "version" : "0.1.0"
      |  }
      |}
      |""".stripMargin

}
