package org.zaproxy.addon.softwareversionreporter;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class SoftwareVersionReporterPassiveScanner extends PluginPassiveScanner {

    private static final Logger LOGGER = LogManager.getLogger(SoftwareVersionReporterPassiveScanner.class);
    private static final int PLUGIN_ID = 90001;
    private final Set raisedOnce = new HashSet();

    @Override
    public int getPluginId() {
        return 90001;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("softwareversionreporter.scanner.name");
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        ExtensionSoftwareVersionReporter ext = ExtensionSoftwareVersionReporter.getInstance();
        if (ext != null) {
            List rules = ext.getCurrentRules();
            if (rules != null && !rules.isEmpty()) {
                String body = msg.getResponseBody().toString();
                SoftwareVersionReporterParam param = ext.getParam();

                for (DetectionRuleLoader.DetectionRule rule : (List<DetectionRuleLoader.DetectionRule>) rules) {
                    String target =
                            "body".equalsIgnoreCase(rule.getType())
                                    ? body
                                    : msg.getResponseHeader().getHeader(rule.getType());
                    if (target != null && !target.isBlank()) {
                        Matcher m = rule.getPattern().matcher(target);
                        if (m.find()) {
                            String software = rule.getSoftware();
                            String version = m.groupCount() >= 1 ? m.group(1) : null;
                            boolean hasVersion = version != null && !version.isBlank();
                            if (hasVersion || param.isEnrichWhenNoVersion()) {
                                String dedupe =
                                        msg.getRequestHeader().getURI().toString()
                                                + "|"
                                                + software
                                                + "|"
                                                + (hasVersion ? version : "no-version");
                                if (this.raisedOnce.add(dedupe)) {
                                    this.raiseSoftwareAlert(msg, software, version, rule, param, target);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private void raiseSoftwareAlert(
            HttpMessage msg,
            String software,
            String version,
            DetectionRuleLoader.DetectionRule rule,
            SoftwareVersionReporterParam param,
            String evidence) {
        EnrichmentResult er = null;
        if (param.isEnrichmentEnabled()) {
            try {
                er =
                        ExtensionSoftwareVersionReporter.getInstance()
                                .getEnrichmentService()
                                .query(software, version, rule.getVendor(), rule.getProduct());
            } catch (Exception e) {
                LOGGER.warn("SVR: enrichment failed for {} {}: {}", software, version, e.getMessage());
            }
        }

        boolean hasVulns =
                er != null && er.getVulnerabilities() != null && !er.getVulnerabilities().isEmpty();
        int risk = 0;
        if (hasVulns) {
            double maxCvss = 0.0F;
            for (Object obj : er.getVulnerabilities()) {
                EnrichmentResult.VulnerabilityInfo vuln = (EnrichmentResult.VulnerabilityInfo) obj;
                double score = vuln.getCvssScore();
                if (score > maxCvss) {
                    maxCvss = score;
                }
            }

            if (maxCvss >= 9.0F) {
                risk = 3;
            } else if (maxCvss >= 7.0F) {
                risk = 2;
            } else if (maxCvss >= 4.0F) {
                risk = 1;
            }
        }

        String title = this.buildTitle(software, version, er);
        String description = this.buildDescription(software, version, er);
        String solution = String.format("Upgrade %s %s to the latest version.", software, version);
        String tags = this.buildTags(software, version, er);
        String references = this.buildReferences(er);
        this.newAlert()
                .setRisk(risk)
                .setConfidence(hasVulns ? 3 : 2)
                .setName(title)
                .setDescription(description)
                .setSolution(solution)
                .setReference(references)
                .setOtherInfo("Tags: " + tags)
                .setEvidence(this.trim(evidence))
                .setMessage(msg)
                .raise();
        LOGGER.debug(
                "SVR: raised alert for {} {} with risk {} ({} vulns)",
                software,
                version,
                risk,
                hasVulns ? er.getVulnerabilities().size() : 0);
    }

    private String buildTitle(String software, String version, EnrichmentResult er) {
        if (er != null && er.getVulnerabilities() != null && !er.getVulnerabilities().isEmpty()) {
            if (er.getVulnerabilities().size() == 1) {
                EnrichmentResult.VulnerabilityInfo vuln =
                        (EnrichmentResult.VulnerabilityInfo) er.getVulnerabilities().get(0);
                String title = vuln.getTitle();
                return title != null
                                && !title.isEmpty()
                                && !title.equals(vuln.getCveId())
                        ? title
                        : String.format("%s in %s %s", vuln.getCveId(), software, version);
            } else {
                return String.format("Multiple Vulnerabilities in %s %s", software, version);
            }
        } else {
            return String.format("%s %s Detected", software, version);
        }
    }

    private String buildDescription(String software, String version, EnrichmentResult er) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Detected %s version %s.\n\n", software, version));
        if (er != null && er.getVulnerabilities() != null && !er.getVulnerabilities().isEmpty()) {
            sb.append(
                    String.format(
                            "Found %d known vulnerabilities:\n\n",
                            er.getVulnerabilities().size()));
            int count = 0;

            for (Object obj : er.getVulnerabilities()) {
                EnrichmentResult.VulnerabilityInfo vuln = (EnrichmentResult.VulnerabilityInfo) obj;
                if (count >= 10) {
                    sb.append(
                            String.format(
                                    "\n... and %d more vulnerabilities (see references for full list)\n",
                                    er.getVulnerabilities().size() - count));
                    break;
                }

                String vulnTitle = vuln.getTitle();
                String cveId = vuln.getCveId();
                String desc = vuln.getDescription();
                double cvss = vuln.getCvssScore();
                sb.append("• ");
                if (vulnTitle != null && !vulnTitle.isEmpty()) {
                    sb.append(vulnTitle);
                } else if (cveId != null && !cveId.isEmpty()) {
                    sb.append(cveId);
                }

                if (cveId != null
                        && !cveId.isEmpty()
                        && (vulnTitle == null || !vulnTitle.contains(cveId))) {
                    sb.append(String.format(" (%s)", cveId));
                }

                if (cvss > 0.0F) {
                    sb.append(String.format(" [CVSS: %.1f]", cvss));
                }

                sb.append(":\n");
                if (desc != null && !desc.isEmpty()) {
                    String cleanDesc =
                            desc.replaceAll("<[^>]+>", "").replaceAll("\\s+", " ").trim();
                    if (cleanDesc.length() > 300) {
                        cleanDesc = cleanDesc.substring(0, 297) + "...";
                    }

                    sb.append(" ").append(cleanDesc).append("\n\n");
                } else {
                    sb.append(" No detailed description available.\n\n");
                }

                ++count;
            }

            return sb.toString();
        } else {
            sb.append("No known vulnerabilities found in public databases.");
            return sb.toString();
        }
    }

    private String buildTags(String software, String version, EnrichmentResult er) {
        Set tags = new LinkedHashSet();
        tags.add("vulnerability");
        if (er != null && er.getSource() != null) {
            tags.add(er.getSource().toLowerCase());
        }

        if (software != null && !software.isEmpty()) {
            tags.add(software.toLowerCase().replaceAll("\\s+", "-"));
        }

        if (version != null && !version.isEmpty()) {
            tags.add(version);
        }

        if (er != null && er.getVulnerabilities() != null) {
            for (Object obj : er.getVulnerabilities()) {
                EnrichmentResult.VulnerabilityInfo vuln = (EnrichmentResult.VulnerabilityInfo) obj;
                if (vuln.getCveId() != null && !vuln.getCveId().isEmpty()) {
                    tags.add(vuln.getCveId());
                }
            }
        }

        return String.join(", ", tags);
    }

    private String buildReferences(EnrichmentResult er) {
        if (er != null && er.getVulnerabilities() != null && !er.getVulnerabilities().isEmpty()) {
            Set refs = new LinkedHashSet();
            for (Object obj : er.getVulnerabilities()) {
                EnrichmentResult.VulnerabilityInfo vuln = (EnrichmentResult.VulnerabilityInfo) obj;
                if (vuln.getCveId() != null && vuln.getCveId().startsWith("CVE-")) {
                    refs.add("https://nvd.nist.gov/vuln/detail/" + vuln.getCveId());
                }
            }

            return String.join("\n", refs);
        } else {
            return "";
        }
    }

    private String trim(String s) {
        if (s == null) {
            return "";
        } else {
            return s.length() > 200 ? s.substring(0, 200) + "..." : s;
        }
    }
}
