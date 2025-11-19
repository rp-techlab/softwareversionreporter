\# Software Version Reporter - OWASP ZAP Add-on



Detect software versions in HTTP responses and enrich findings with vulnerability intelligence from multiple providers.



---



\## Features



\- Passive scanning for software version detection from HTTP headers and bodies.

\- Dynamic detection rules loaded from external TSV files.

\- Vulnerability enrichment via public APIs (NVD, Vulners, VulDB).

\- User-friendly configuration and API key management via ZAP Options panel.

\- Support for custom detection rules with live reload.

\- Detailed vulnerability alerts with CVE info.



---



\## Installation



1\. Clone this repo into ZAP's `zap-extensions/addOns` folder.

2\. Build and copy the add-on:

&nbsp;  ```

&nbsp;  ./gradlew :addOns:softwareversionreporter:clean :addOns:softwareversionreporter:build

&nbsp;  ./gradlew :addOns:softwareversionreporter:copyZapAddOn --into=$HOME/.ZAP/plugin/

&nbsp;  ```

3\. Restart ZAP. The add-on should appear in the scanner and options.



---



\## Usage



\- Configure API keys and enable enrichment in \*\*Options → Software Version Reporter\*\*.

\- Load or reload detection rules (TSV files) in the Options panel.

\- The add-on passively detects software versions during web catalog scans.

\- Vulnerabilities appear as alerts with enriched info when enabled.



---



\## Logging \& Debugging



\- Extension logs are integrated with ZAP logs at level DEBUG under:

&nbsp; `org.zaproxy.addon.softwareversionreporter`

\- Enable debug logging for `softwareversionreporter` in ZAP logging settings to trace detection, enrichment, and rule loading.

\- Common issues like failed enrichment due to missing API keys, malformed rules, or network failures are logged here.



---



\## Development



\- The add-on is fully Gradle and ZAP Add-on Framework compliant.

\- Follow standard ZAP add-on development practices.

\- Dynamic detection rules and configurations allow easy future extension.

\- To test changes, rebuild and copy the add-on as above.



---



\## Contribution and Contact



Created and maintained by Raghavendra patil].



\- LinkedIn: https://www.linkedin.com/in/raghavendra-patil-8a0330197

\- GitHub: https://github.com/raghu844/




Pull requests, issues, and feature requests welcome.



---



\## License



This add-on is licensed under the Apache 2.0 License. See \[LICENSE](LICENSE) file.



```





