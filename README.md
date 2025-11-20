Here is the updated clean and concise README in Markdown format with the **Logging section removed**, and a detailed **API Keys configuration and usage tutorial** added, including placeholders for screenshots:

***

# Software Version Reporter - OWASP ZAP Add-on

Detect software versions in HTTP responses and enrich findings with vulnerability intelligence.

***

## Features

- Passive scanning for software version detection in HTTP headers and response bodies.
- Dynamic loading of detection rules from external TSV files.
- Vulnerability enrichment using public APIs (NVD, Vulners, VulDB).
- Easy API key management via ZAP Options panel.
- Support for custom detection rules with live reload.
- Detailed vulnerability alerts with CVE references.

***

## Installation

1. Clone into ZAP’s addOns folder:

```bash
git clone https://github.com/rp-techlab/softwareversionreporter.git zap-extensions/addOns/softwareversionreporter
```

2. Build and deploy:

```bash
./gradlew :addOns:softwareversionreporter:clean :addOns:softwareversionreporter:build
./gradlew :addOns:softwareversionreporter:copyZapAddOn --into=$HOME/.ZAP/plugin/
```

3. Restart ZAP.

***

## API Keys Configuration

1. Open OWASP ZAP.

2. Navigate to **Options → Software Version Reporter**.

3. Locate the **API Keys** section.

4. Enter your API keys for vulnerability data providers:

   - **NVD API Key**: Obtain from [NVD NIST](https://nvd.nist.gov/developers/request-an-api-key) (optional but recommended for higher rate limits).

   - **Vulners API Key**: Register at [Vulners](https://vulners.com) if you intend to use this service.

   - **VulDB API Key**: Obtain from [VulDB](https://vuldb.com) (optional).

5. Enable or disable enrichment for each source using the provided toggles.

6. Click **Save** or **Apply** to persist your settings.

<img width="922" height="718" alt="image" src="https://github.com/user-attachments/assets/59bfeb47-0717-450a-afba-21e36e63cf33" />


  
*Placeholder: Add screenshot of API keys input panel here*

***

## Loading Detection Rules

- Rules are read dynamically from TSV files.

- To load or reload detection rules:

  1. Go to **Options → Software Version Reporter**.

  2. Use the **Load Rules** or **Reload Rules** button to select a TSV file or reload the current rules.

  3. Rules support custom detection patterns and can be updated without restarting ZAP.

<img width="727" height="460" alt="image" src="https://github.com/user-attachments/assets/84151fc0-b4a8-4ce7-b353-61c501e9418c" />

- Alternatively, place custom rule files named `detection-rules.tsv` in:

```bash
~/.ZAP/softwareversionreporter/detection-rules.tsv
```

They will be auto-loaded by the add-on.

***

## Usage

- Perform web scans as usual in ZAP.

- The Software Version Reporter extension passively detects software versions from HTTP response headers and bodies during scanning.

- Detected software versions enriched with vulnerability data appear as alerts in the **Alerts** tab.

<img width="505" height="433" alt="image" src="https://github.com/user-attachments/assets/9caa6b8b-d7bc-4de7-981e-f68319b1539e" />


***

## Contribution & Contact

Created and maintained by Raghavendra Patil.

- GitHub: [https://github.com/raghu844](https://github.com/raghu844)

- LinkedIn: [https://www.linkedin.com/in/raghavendra-patil-8a0330197](https://www.linkedin.com/in/raghavendra-patil-8a0330197)

Pull requests, issues, and feature requests are welcome.

***

## License

Licensed under Apache 2.0 License. See LICENSE file.

***

Let me know if you need help preparing any of the screenshots or additional sections!
