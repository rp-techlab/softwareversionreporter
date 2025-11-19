package org.zaproxy.addon.softwareversionreporter.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;

public class SmartReportFormatter {
   public RenderedReport render(EnrichmentResult er, String provider, List zapTags) {
      RenderedReport rr = new RenderedReport();
      List<EnrichmentResult.VulnerabilityInfo> vulns = (List<EnrichmentResult.VulnerabilityInfo>)(er != null && er.getVulnerabilities() != null ? er.getVulnerabilities() : new ArrayList());
      if (vulns.size() == 1) {
         String t = safe(((EnrichmentResult.VulnerabilityInfo)vulns.get(0)).getTitle(), safe(((EnrichmentResult.VulnerabilityInfo)vulns.get(0)).getCveId(), "Vulnerability"));
         rr.title = t;
      } else {
         String var10001 = safe(er != null ? er.getSoftware() : null, "software");
         rr.title = "Multiple Vulnerabilities: " + var10001 + " " + safe(er != null ? er.getVersion() : null, "version");
      }

      StringBuilder sb = new StringBuilder();

      for(EnrichmentResult.VulnerabilityInfo v : vulns) {
         String name = safe(v.getTitle(), safe(v.getCveId(), "Vulnerability"));
         String d = safe(v.getShortDescription(), safe(v.getDescription(), ""));
         String cve = safe(v.getCveId(), "");
         if (!cve.isBlank()) {
            sb.append(name).append(": ").append(d).append(" ").append(cve).append("\n");
         } else {
            sb.append(name).append(": ").append(d).append("\n");
         }

         if (v.getLink() != null && !v.getLink().isBlank()) {
            rr.links.add(v.getLink());
         }
      }

      rr.description = sb.toString().trim();
      String var21 = safe(er != null ? er.getSoftware() : null, "software");
      rr.solution = "Upgrade " + var21 + " " + safe(er != null ? er.getVersion() : null, "version") + " to the latest version.";
      double best = (double)0.0F;

      for(EnrichmentResult.VulnerabilityInfo v : vulns) {
         best = Math.max(best, v.getCvssScore());
      }

      rr.score = best;
      List<String> tags = new ArrayList();
      tags.add("vulnerability");
      if (provider != null && !provider.isBlank()) {
         tags.add(provider.toLowerCase(Locale.ROOT));
      }

      if (er != null) {
         if (er.getSoftware() != null) {
            tags.add(er.getSoftware());
         }

         if (er.getVersion() != null) {
            tags.add(er.getVersion());
         }
      }

      List<String> cves = new ArrayList();

      for(EnrichmentResult.VulnerabilityInfo v : vulns) {
         String c = v.getCveId();
         if (c != null && !c.isBlank()) {
            cves.add(c);
         }
      }

      if (!cves.isEmpty()) {
         tags.add(String.join(", ", cves));
      }

      if (zapTags != null) {
         tags.addAll(zapTags);
      }

      rr.tags = String.join(", ", tags);
      return rr;
   }

   private static String safe(String s, String d) {
      return s != null && !s.isBlank() ? s : d;
   }

   public static class RenderedReport {
      public String title;
      public String description;
      public String solution;
      public String tags;
      public double score;
      public List links = new ArrayList();
   }
}
