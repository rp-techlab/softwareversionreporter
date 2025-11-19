package org.zaproxy.addon.softwareversionreporter.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.softwareversionreporter.VulnerabilityEnrichmentService;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;

public class ProviderHealthCheck {
   private static final Logger LOGGER = LogManager.getLogger(ProviderHealthCheck.class);

   public static void run(VulnerabilityEnrichmentService svc) {
      try {
         EnrichmentResult v = svc.query("nginx", "1.21.6", "nginx", "nginx");
         EnrichmentResult n = svc.query("php", "5.6.0", "php", "php");
         LOGGER.info("Health: Vulners={} NVD={}", v == null ? 0 : v.getVulnerabilities().size(), n == null ? 0 : n.getVulnerabilities().size());
      } catch (Exception e) {
         LOGGER.warn("Provider health check failed: {}", e.toString());
      }

   }
}
