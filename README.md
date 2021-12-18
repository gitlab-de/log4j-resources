# 💡 Log4j CVE-2021-44228, CVE-2021-45046, CVE-2021-45105 Resources 

This repository is designed to be a collection of resources to learn about, detect and mitigate the impact of the Log4j vulnerability - more formally known as [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228).

Below you can find a set of links to resources organized by topic area.  If you want to add resources, you can [fork](https://gitlab.com/gitlab-de/log4j-resources/-/forks/new) this repository on GitLab.com and create a merge request. [This repository on GitLab](https://gitlab.com/gitlab-de/log4j-resources) is mirrored to [GitHub](https://github.com/gitlab-de/log4j-resources). 

#### Table of content

* [About the vulnerability](#-about-the-vulnerability)
  * [Software updates](#-software-updates)
  * [CVE information](#-cve-information)
  * [Security advisories](#-security-advisories)
  * [Other](#-other)
* [Detecting the vulnerability](#-detecting-the-vulnerability)
  * [Security Vendors](#-security-vendors)
  * [Guides](#-guides)
  * [Community tools and articles](#-community-tools-and-articles)
* [Mitigating the vulnerability](#-mitigating-the-vulnerability)


## ❔ About the vulnerability

Apache Log4j, versions 2.0-2.14.1 have a vulnerability to remote code execution (RCE). It is remotely exploitable without authentication, i.e., attackers may exploit it over a network without the need for a username and password.

New vulnverabilities have been discovered and fixed, see _Software updates_ below for the timeline.

### 📦 Software updates

Upgrade log4j to the latest release to fix the vulnerabilities.

- [log4j 2.17.0](https://logging.apache.org/log4j/2.x/changes-report.html#a2.17.0) fixes [CVE-2021-45105](https://logging.apache.org/log4j/2.x/security.html#CVE-2021-45105), where log4j does not always protect from infinite recursion, leading to DoS attacks.
- [log4j 2.16.0](https://logging.apache.org/log4j/2.x/changes-report.html#a2.16.0) removes support for message lookups, and disables JNDI by default. Fixes [CVE-2021-45046](https://logging.apache.org/log4j/2.x/security.html#CVE-2021-45046) with raised critical severity, RCE possibility. 
- [log4j 2.15.0](https://logging.apache.org/log4j/2.x/changes-report.html#a2.15.0) fixes the vulnerability in [CVE-2021-44228](https://logging.apache.org/log4j/2.x/security.html#CVE-2021-44228) but left JNDI lookups enabled by default.

### 📄 CVE Information

- [CVE-2021-45105](https://nvd.nist.gov/vuln/detail/CVE-2021-45105) from NIST
- [CVE-2021-45105](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105) from MITRE
- [CVE-2021-45046](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046) from MITRE
- [CVE-2021-45046](https://access.redhat.com/security/cve/cve-2021-45046) from Red Hat
- [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228) from MITRE
- [CVE-2021-44228](https://www.oracle.com/security-alerts/alert-cve-2021-44228.html) from Oracle

### 💬 Security Advisories

- [This GitHub gist](https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592) contains an extensive list of the various security advisories from cloud, software, and SaaS companies about CVE-2021-44228.
- [CISA Log4j (CVE-2021-44228) Vulnerability Guidance](https://github.com/cisagov/log4j-affected-db)
- [Updates and actions to address Log4j CVE 2021 44228 and CVE 2021 45046 in GitLab](https://about.gitlab.com/blog/2021/12/15/updates-and-actions-to-address-logj-in-gitlab/)
- [Jenkins](https://www.jenkins.io/blog/2021/12/10/log4j2-rce-CVE-2021-44228/)

### 📖 Other

- [Software related to or impacted by the Log4j vulnerability](https://github.com/NCSC-NL/log4shell/tree/main/software)
- [List of impact on manufacturers and components summary from the Internet community](https://github.com/YfryTchsGD/Log4jAttackSurface)
- [Awesome Log4Shell](https://github.com/snyk-labs/awesome-log4shell)
- [‘The Internet Is on Fire’](https://www.wired.com/story/log4j-flaw-hacking-internet/) by Wired

## 🔥 Detecting the vulnerability

### 🚒 Security Vendors

- [Checkmarx](https://checkmarx.com/blog/apache-log4j-remote-code-execution-cve-2021-44228/)
- [Contrast Security](https://www.contrastsecurity.com/security-influencers/0-day-detection-of-log4j2-vulnerability)
- [Docker](https://www.docker.com/blog/apache-log4j-2-cve-2021-44228/)
- [Elastic](https://www.elastic.co/blog/detecting-log4j2-with-elastic-security)
- [GitLab](https://about.gitlab.com/blog/2021/12/15/use-gitlab-to-detect-vulnerabilities/)
- [Synk](https://snyk.io/blog/find-fix-log4shell-quickly-snyk/)
- [WhiteSource](https://www.whitesourcesoftware.com/resources/blog/log4j-vulnerability-cve-2021-44228/)
- [Veracode](https://www.veracode.com/blog/security-news/urgent-analysis-and-remediation-guidance-log4j-zero-day-rce-cve-2021-44228)

### 🏗️ Guides

- [Container Scanning](container_scanning.md)

### 📈 Community tools and articles

Community projects and discussions; they have not been tested. Be advised to evaluate and asses their usability on your own. 

- [GitLab search tools forum topic](https://forum.gitlab.com/t/search-code-across-all-projects/2263/19?u=dnsmichi)
- [Mitigate Log4j2 / Log4Shell in Elasticsearch](https://xeraa.net/blog/2021_mitigate-log4j2-log4shell-elasticsearch/) by Philipp Krenn

## 🛡️ Mitigating the vulnerability

The best way to mitigate the vulnerability is to update any application using Log4j to the latest version (see _Software Updates_ section above).  However, there have been many other discussions of how to mitigate the vulnerability short of that.

- Disable message lookups.  These are availabe in Log4j 2.10 - 2.14.1 and requires restarting the process.
  - Adding `-Dlog4j2.formatMsgNoLookups=true` to processes running Log4j 2.10 - 2.14.1.  
  - Setting an environmental variable `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`
- For versions 2.0-beta9 to 2.10.0, you could remove the JndiLookup class by running the code below and restarting the process
  - `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`
- Without restarting the process, you could apply this [hot patch](https://github.com/corretto/hotpatch-for-apache-log4j2) which injects a Java agent into running processes to patch the issue.
