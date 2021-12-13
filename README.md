# Log4j CVE-2021-44228 Resources 

This repository is designed to be a collection of resources to learn about, detect and mitigate the impact of the Log4j vulnerability - more formally known as [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228).

Below you can find a set of links to resources organized by topic area.  If you want to add resources, you can [fork](https://gitlab.com/gitlab-de/log4j-resources/-/forks/new) this repository and create a merge request.

## About the vulnerability
Apache Log4j, versions 2.0-2.14.1 have a vulnerability to remote code execution (RCE). It is remotely exploitable without authentication, i.e., attackers may exploit it over a network without the need for a username and password.

### CVE Information
- [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228) from MITRE
- [CVE-2021-44228](https://www.oracle.com/security-alerts/alert-cve-2021-44228.html) from Oracle

### Security Advisories
- [This GitHub gist](https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592) contains an extensive list of the various security advisories from cloud, software, and SaaS companies about CVE-2021-44228.

### Other
- [Software related to or impacted by the Log4j vulnerability](https://github.com/NCSC-NL/log4shell/tree/main/software)
- [List of impact on manufacturers and components summary from the Internet community](https://github.com/YfryTchsGD/Log4jAttackSurface)
- [‘The Internet Is on Fire’](https://www.wired.com/story/log4j-flaw-hacking-internet/) by Wired

## Detecting the vulnerability
### Security Vendors
- [Checkmarx](https://checkmarx.com/blog/apache-log4j-remote-code-execution-cve-2021-44228/)
- [Contrast Security](https://www.contrastsecurity.com/security-influencers/0-day-detection-of-log4j2-vulnerability)
- [GitLab dependancy scanning](https://docs.gitlab.com/ee/user/application_security/dependency_scanning/)
- [Synk](https://snyk.io/blog/find-fix-log4shell-quickly-snyk/)
- [WhiteSource](https://www.whitesourcesoftware.com/resources/blog/log4j-vulnerability-cve-2021-44228/)
- [Veracode](https://www.veracode.com/blog/security-news/urgent-analysis-and-remediation-guidance-log4j-zero-day-rce-cve-2021-44228)

### CI/CD 
- [Jenkins][https://www.jenkins.io/blog/2021/12/10/log4j2-rce-CVE-2021-44228/]

## Mitigating the vulnerability
The best way to mitigate the vulnerability is to update any application using Log4j to version 2.15.0+.  However, there have been many other discussions of how to mitigate the vulnerability short of that.

- Disable message lookups.  These are availabe in Log4j 2.10 - 2.14.1 and requires restarting the process.
  - Adding `-Dlog4j2.formatMsgNoLookups=true` to processes running Log4j 2.10 - 2.14.1.  
  - Setting an environmental variable `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`
- For versions 2.0-beta9 to 2.10.0, you could remove the JndiLookup class by running the code below and restarting the process
  - `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`
- Without restarting the process, you could apply this [hot patch](https://github.com/corretto/hotpatch-for-apache-log4j2) which injects a Java agent into running processes to patch the issue.
