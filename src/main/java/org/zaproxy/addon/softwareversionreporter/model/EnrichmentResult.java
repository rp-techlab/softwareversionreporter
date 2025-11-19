package org.zaproxy.addon.softwareversionreporter.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class EnrichmentResult {

    private String software;
    private String version;
    private String source;
    private String cpe;
    private List vulnerabilities = new ArrayList();

    public EnrichmentResult() {
    }

    public EnrichmentResult(String software, String version) {
        this.software = software;
        this.version = version;
    }

    public String getSoftware() {
        return this.software;
    }

    public void setSoftware(String software) {
        this.software = software;
    }

    public String getVersion() {
        return this.version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getSource() {
        return this.source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getCpe() {
        return this.cpe;
    }

    public void setCpe(String cpe) {
        this.cpe = cpe;
    }

    public List getVulnerabilities() {
        return this.vulnerabilities;
    }

    public void setVulnerabilities(List vulnerabilities) {
        this.vulnerabilities = (List)(vulnerabilities == null ? new ArrayList() : vulnerabilities);
    }

    public boolean hasVulnerabilities() {
        return this.vulnerabilities != null && !this.vulnerabilities.isEmpty();
    }

    public static class VulnerabilityInfo {

        private String cveId;
        private String title;
        private String shortDescription;
        private String description;
        private String link;
        private double cvssScore;
        private String severity;
        private List references = new ArrayList();

        public String getCveId() {
            return this.cveId;
        }

        public void setCveId(String cveId) {
            this.cveId = cveId;
        }

        public String getTitle() {
            return this.title;
        }

        public void setTitle(String title) {
            this.title = title;
        }

        public String getShortDescription() {
            return this.shortDescription;
        }

        public void setShortDescription(String shortDescription) {
            this.shortDescription = shortDescription;
        }

        public String getDescription() {
            return this.description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getLink() {
            return this.link;
        }

        public void setLink(String link) {
            this.link = link;
        }

        public double getCvssScore() {
            return this.cvssScore;
        }

        public void setCvssScore(double cvssScore) {
            this.cvssScore = cvssScore;
        }

        public String getSeverity() {
            return this.severity;
        }

        public void setSeverity(String severity) {
            this.severity = severity;
        }

        public List getReferences() {
            return this.references;
        }

        public void setReferences(List references) {
            this.references = (List)(references == null ? new ArrayList() : references);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            } else if (!(o instanceof VulnerabilityInfo)) {
                return false;
            } else {
                VulnerabilityInfo that = (VulnerabilityInfo)o;
                return Objects.equals(this.cveId, that.cveId)
                        && Objects.equals(this.title, that.title)
                        && Objects.equals(this.link, that.link);
            }
        }

        @Override
        public int hashCode() {
            return Objects.hash(new Object[]{this.cveId, this.title, this.link});
        }
    }
}
