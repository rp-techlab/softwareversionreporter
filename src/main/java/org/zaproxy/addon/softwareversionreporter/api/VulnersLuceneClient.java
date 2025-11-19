package org.zaproxy.addon.softwareversionreporter.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import org.zaproxy.addon.softwareversionreporter.VulnerabilityMappers;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;

public class VulnersLuceneClient {
   private static final ObjectMapper M = new ObjectMapper();

   public EnrichmentResult lucene(String software, String version, String json) throws Exception {
      EnrichmentResult er = new EnrichmentResult(software, version);
      er.setSource("Vulners");
      JsonNode root = M.readTree(json);
      List<EnrichmentResult.VulnerabilityInfo> out = new ArrayList();
      JsonNode hits = root.path("data").path("search");
      if (hits.isArray()) {
         for(JsonNode it : hits) {
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
