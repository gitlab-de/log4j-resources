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
- [GitLab dependancy scanning](https://docs.gitlab.com/ee/user/application_security/dependency_scanning/)
- [Synk](https://snyk.io/blog/find-fix-log4shell-quickly-snyk/)

## Mitigating the vulnerability

