package org.zaproxy.addon.softwareversionreporter;

import org.apache.commons.configuration.Configuration;

public class SoftwareVersionReporterParam {
   private static final String ENRICHMENT_ENABLED_KEY = "softwareversionreporter.enrichment.enabled";
   private static final String API_PROVIDER_KEY = "softwareversionreporter.enrichment.provider";
   private static final String NVD_API_KEY = "softwareversionreporter.nvd.apikey";
   private static final String VULNERS_API_KEY = "softwareversionreporter.vulners.apikey";
   private static final String VULDB_API_KEY = "softwareversionreporter.vuldb.apikey";
   private static final String ENRICH_ON_NO_VERSION_KEY = "softwareversionreporter.enrichment.whenNoVersion";
   private boolean enrichmentEnabled = false;
   private String apiProvider = "nvd";
   private String nvdApiKey = "";
   private String vulnersApiKey = "";
   private String vuldbApiKey = "";
   private boolean enrichWhenNoVersion = false;

   public void parse(Configuration conf) {
      if (conf != null) {
         this.enrichmentEnabled = conf.getBoolean("softwareversionreporter.enrichment.enabled", this.enrichmentEnabled);
         this.apiProvider = conf.getString("softwareversionreporter.enrichment.provider", this.apiProvider);
         this.nvdApiKey = conf.getString("softwareversionreporter.nvd.apikey", this.nvdApiKey);
         this.vulnersApiKey = conf.getString("softwareversionreporter.vulners.apikey", this.vulnersApiKey);
         this.vuldbApiKey = conf.getString("softwareversionreporter.vuldb.apikey", this.vuldbApiKey);
         this.enrichWhenNoVersion = conf.getBoolean("softwareversionreporter.enrichment.whenNoVersion", this.enrichWhenNoVersion);
      }
   }

   public void save(Configuration conf) {
      if (conf != null) {
         conf.setProperty("softwareversionreporter.enrichment.enabled", this.enrichmentEnabled);
         conf.setProperty("softwareversionreporter.enrichment.provider", this.apiProvider);
         conf.setProperty("softwareversionreporter.nvd.apikey", this.nvdApiKey);
         conf.setProperty("softwareversionreporter.vulners.apikey", this.vulnersApiKey);
         conf.setProperty("softwareversionreporter.vuldb.apikey", this.vuldbApiKey);
         conf.setProperty("softwareversionreporter.enrichment.whenNoVersion", this.enrichWhenNoVersion);
      }
   }

   public boolean isEnrichmentEnabled() {
      return this.enrichmentEnabled;
   }

   public void setEnrichmentEnabled(boolean enabled) {
      this.enrichmentEnabled = enabled;
   }

   public String getApiProvider() {
      return this.apiProvider;
   }

   public void setApiProvider(String provider) {
      this.apiProvider = provider;
   }

   public String getNvdApiKey() {
      return this.nvdApiKey;
   }

   public void setNvdApiKey(String key) {
      this.nvdApiKey = key;
   }

   public String getVulnersApiKey() {
      return this.vulnersApiKey;
   }

   public void setVulnersApiKey(String key) {
      this.vulnersApiKey = key;
   }

   public String getVuldbApiKey() {
      return this.vuldbApiKey;
   }

   public void setVuldbApiKey(String key) {
      this.vuldbApiKey = key;
   }

   public boolean isEnrichWhenNoVersion() {
      return this.enrichWhenNoVersion;
   }

   public void setEnrichWhenNoVersion(boolean v) {
      this.enrichWhenNoVersion = v;
   }
}
