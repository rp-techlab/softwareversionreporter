package org.zaproxy.addon.softwareversionreporter.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;

public class NVDClient {
   private static final Logger LOGGER = LogManager.getLogger(NVDClient.class);
   private static final String NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
   private static final ObjectMapper mapper = new ObjectMapper();

   public EnrichmentResult queryByCpe(String software, String version, String cpe) {
      long start = System.currentTimeMillis();
      LOGGER.info("SVR:NVD starting query cpe={} software={} version={}", cpe, software, version);

      try {
         String cpeName = URLEncoder.encode(cpe, StandardCharsets.UTF_8);
         String url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=" + cpeName;
         LOGGER.debug("SVR:NVD URL={}", url);
         HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15L)).build();
         HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).header("Accept", "application/json").header("User-Agent", "OWASP-ZAP-SoftwareVersionReporter/1.0").timeout(Duration.ofSeconds(30L)).GET().build();
         HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
         long elapsed = System.currentTimeMillis() - start;
         int status = response.statusCode();
         String body = (String)response.body();
         LOGGER.info("SVR:NVD HTTP response status={} bytes={} ms={}", status, body.length(), elapsed);
         if (status != 200) {
            LOGGER.warn("SVR:NVD error status={} cpe={} ms={} body={}", status, cpe, elapsed, body.substring(0, Math.min(200, body.length())));
            return null;
         } else {
            JsonNode root = mapper.readTree(body);
            JsonNode vulnerabilities = root.path("vulnerabilities");
            List<EnrichmentResult.VulnerabilityInfo> vulns = new ArrayList();
            if (vulnerabilities.isArray()) {
               LOGGER.info("SVR:NVD found {} vulnerability records", vulnerabilities.size());

               for(JsonNode item : vulnerabilities) {
                  JsonNode cveNode = item.path("cve");
                  String cveId = cveNode.path("id").asText((String)null);
                  String description = this.extractDescription(cveNode);
                  double cvssScore = this.extractCvssScore(cveNode);
                  if (cveId != null) {
                     EnrichmentResult.VulnerabilityInfo vuln = new EnrichmentResult.VulnerabilityInfo();
                     vuln.setCveId(cveId);
                     vuln.setTitle(cveId);
                     vuln.setDescription(description);
                     vuln.setCvssScore(cvssScore);
                     vulns.add(vuln);
                     LOGGER.debug("SVR:NVD added {} score={}", cveId, cvssScore);
                  }
               }
            } else {
               LOGGER.info("SVR:NVD no vulnerabilities array in response");
            }

            LOGGER.info("SVR:NVD status={} items={} ms={} bytes={} cpe={}", status, vulns.size(), elapsed, body.length(), cpe);
            EnrichmentResult result = new EnrichmentResult(software, version);
            result.setCpe(cpe);
            result.setSource("NVD");
            result.setVulnerabilities(vulns);
            return result;
         }
      } catch (Exception e) {
         long elapsed = System.currentTimeMillis() - start;
         LOGGER.error("SVR:NVD exception cpe={} ms={} error={}", cpe, elapsed, e.getMessage(), e);
         return null;
      }
   }

   private String extractDescription(JsonNode cveNode) {
      JsonNode descriptions = cveNode.path("descriptions");
      return descriptions.isArray() && descriptions.size() > 0 ? descriptions.get(0).path("value").asText("") : "";
   }

   private double extractCvssScore(JsonNode cveNode) {
      JsonNode metrics = cveNode.path("metrics");
      JsonNode cvssV31 = metrics.path("cvssMetricV31");
      if (cvssV31.isArray() && cvssV31.size() > 0) {
         return cvssV31.get(0).path("cvssData").path("baseScore").asDouble((double)0.0F);
      } else {
         JsonNode cvssV30 = metrics.path("cvssMetricV30");
         if (cvssV30.isArray() && cvssV30.size() > 0) {
            return cvssV30.get(0).path("cvssData").path("baseScore").asDouble((double)0.0F);
         } else {
            JsonNode cvssV2 = metrics.path("cvssMetricV2");
            return cvssV2.isArray() && cvssV2.size() > 0 ? cvssV2.get(0).path("cvssData").path("baseScore").asDouble((double)0.0F) : (double)0.0F;
         }
      }
   }
}
