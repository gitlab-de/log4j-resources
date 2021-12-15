# 📦 Container Scanning

Trivy and Grype are integrated into [GitLab Container Scanning (Ultimate)](https://docs.gitlab.com/ee/user/application_security/container_scanning/).

The following guides describe how use the Open Source on the CLI for your own integrations. 

- [Trivy](#trivy)
- [Grype](#grype)

## Trivy

Follow the documentation to install [Trivy](https://aquasecurity.github.io/trivy/v0.21.2/getting-started/installation/).

Trivy supports [different output formats](https://aquasecurity.github.io/trivy/v0.21.2/getting-started/cli/image/) for the image command. Combine this with [jq](/blog/2021/04/21/devops-workflows-json-format-jq-ci-cd-lint/) and parse the data structure to filter only by packages containing `log4j` as string. 

```
$trivy image --format json --output trivy_report.json registry.gitlab.com/gitlab-de/playground/log4shell-vulnerable-app:latest

$ cat trivy_report.json | jq -c '.Results' | jq -c '.[]' | jq -c '.Vulnerabilities' | jq -c '.[]' | jq -c 'select(.PkgName | contains ("log4j") )' | jq

{
  "VulnerabilityID": "CVE-2021-45046",
  "PkgName": "org.apache.logging.log4j:log4j-core",
  "InstalledVersion": "2.14.1",
  "FixedVersion": "2.16.0",
  "Layer": {
    "DiffID": "sha256:082e18dc6a9e8f17eb91102a5eeb97ad78a83f3e3edcd5671bbc9dd8821410a2"
  },
  "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-45046",
  "Title": "log4j-core: DoS in log4j 2.x with thread context message pattern and context lookup pattern (incomplete fix for CVE-2021-44228)",
  "Description": "It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in a denial of service (DOS) attack. Log4j 2.15.0 restricts JNDI LDAP lookups to localhost by default. Note that previous mitigations involving configuration such as to set the system property `log4j2.noFormatMsgLookup` to `true` do NOT mitigate this specific vulnerability. Log4j 2.16.0 fixes this issue by removing support for message lookup patterns and disabling JNDI functionality by default. This issue can be mitigated in prior releases (<2.16.0) by removing the JndiLookup class from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class).",
  "Severity": "LOW",
  "CVSS": {
    "redhat": {
      "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
      "V3Score": 3.7
    }
  },
  "References": [
    "http://www.openwall.com/lists/oss-security/2021/12/14/4",
    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046",
    "https://github.com/advisories/GHSA-7rjr-3q55-vv33",
    "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
    "https://issues.apache.org/jira/browse/LOG4J2-3221",
    "https://lists.apache.org/thread/83y7dx5xvn3h5290q1twn16tltolv88f",
    "https://logging.apache.org/log4j/2.x/security.html",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-45046",
    "https://www.cve.org/CVERecord?id=CVE-2021-44228",
    "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00646.html",
    "https://www.openwall.com/lists/oss-security/2021/12/14/4"
  ],
  "PublishedDate": "2021-12-14T19:15:00Z",
  "LastModifiedDate": "2021-12-15T03:15:00Z"
}
```

Trivy provides more [insights for CI/CD integrations](https://aquasecurity.github.io/trivy/v0.21.2/advanced/integrations/gitlab-ci/) in the documentation. 

## Grype 

Follow the documentation to install [Grype](https://github.com/anchore/grype#installation).

You can build the same query with Grype and jq, navigating the data structure and filtering for `log4j` in the description. 

```
$ grype --output json registry.gitlab.com/gitlab-de/playground/log4shell-vulnerable-app:latest > grype_report.json

$ cat grype_report.json| jq -c '.matches' | jq -c '.[]' | jq -c '.vulnerability' | jq -c 'select( .description | contains ("log4j") )' | jq

{
  "id": "CVE-2021-44228",
  "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
  "namespace": "nvd",
  "severity": "Critical",
  "urls": [
    "https://logging.apache.org/log4j/2.x/security.html",
    "http://www.openwall.com/lists/oss-security/2021/12/10/1",
    "http://www.openwall.com/lists/oss-security/2021/12/10/2",
    "http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html",
    "https://security.netapp.com/advisory/ntap-20211210-0007/",
    "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd",
    "http://www.openwall.com/lists/oss-security/2021/12/10/3",
    "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0032",
    "https://www.oracle.com/security-alerts/alert-cve-2021-44228.html",
    "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU57UJDCFIASIO35GC55JMKSRXJMCDFM/",
    "http://www.openwall.com/lists/oss-security/2021/12/13/1",
    "http://www.openwall.com/lists/oss-security/2021/12/13/2",
    "https://twitter.com/kurtseifried/status/1469345530182455296",
    "https://lists.debian.org/debian-lts-announce/2021/12/msg00007.html",
    "https://www.debian.org/security/2021/dsa-5020",
    "https://cert-portal.siemens.com/productcert/pdf/ssa-661247.pdf"
  ],
  "description": "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. In previous releases (>2.10) this behavior can be mitigated by setting system property \"log4j2.formatMsgNoLookups\" to “true” or it can be mitigated in prior releases (<2.10) by removing the JndiLookup class from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class).",
  "cvss": [
    {
      "version": "2.0",
      "vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
      "metrics": {
        "baseScore": 9.3,
        "exploitabilityScore": 8.6,
        "impactScore": 10
      },
      "vendorMetadata": {}
    },
    {
      "version": "3.1",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "metrics": {
        "baseScore": 10,
        "exploitabilityScore": 3.9,
        "impactScore": 6
      },
      "vendorMetadata": {}
    }
  ],
  "fix": {
    "versions": [],
    "state": "unknown"
  },
  "advisories": []
}
```

