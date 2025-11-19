package org.zaproxy.addon.softwareversionreporter.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import org.zaproxy.addon.softwareversionreporter.VulnerabilityMappers;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;

public class VulnersAuditClient {
   private static final ObjectMapper M = new ObjectMapper();

   public EnrichmentResult audit(String software, String version, String json) throws Exception {
      EnrichmentResult er = new EnrichmentResult(software, version);
      er.setSource("Vulners");
      JsonNode root = M.readTree(json);
      List<EnrichmentResult.VulnerabilityInfo> out = new ArrayList();
      JsonNode items = root.path("data").path("search");
      if (items.isArray()) {
         for(JsonNode it : items) {
            JsonNode src = it.has("_source") ? it.path("_source") : it;
            EnrichmentResult.VulnerabilityInfo vi = VulnerabilityMappers.mapVulnersItem(src);
            if (vi != null) {
               out.add(vi);
            }
         }
      }

      er.setVulnerabilities(out);
      return er;
   }
}
