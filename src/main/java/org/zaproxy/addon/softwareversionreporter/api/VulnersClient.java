package org.zaproxy.addon.softwareversionreporter.api;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.softwareversionreporter.model.EnrichmentResult;

public class VulnersClient {
   private static final Logger LOGGER = LogManager.getLogger(VulnersClient.class);
   private static final String API_BASE = "https://vulners.com/api/v3";
   private String apiKey;

   public VulnersClient(String apiKey) {
      this.apiKey = apiKey;
   }

   public EnrichmentResult queryByProduct(String software, String version, String vendor, String product) {
      if (this.apiKey != null && !this.apiKey.trim().isEmpty()) {
         long start = System.currentTimeMillis();

         try {
            String query = String.format("%s %s", software, version);
            String encodedQuery = URLEncoder.encode(query, "UTF-8");
            String urlStr = String.format("%s/search/lucene/?query=%s&skip=0&size=50", "https://vulners.com/api/v3", encodedQuery);
            LOGGER.info("SVR:Vulners starting query software={} version={} query={}", software, version, query);
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection)url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("X-Api-Key", this.apiKey);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            int status = conn.getResponseCode();
            long responseTime = System.currentTimeMillis() - start;
            LOGGER.info("SVR:Vulners HTTP response status={} ms={}", status, responseTime);
            if (status != 200) {
               LOGGER.warn("SVR:Vulners error status={}", status);
               return null;
            } else {
               StringBuilder response = new StringBuilder();
               BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));

               String line;
               try {
                  while((line = br.readLine()) != null) {
                     response.append(line);
                  }
               } catch (Throwable var28) {
                  try {
                     br.close();
                  } catch (Throwable var27) {
                     var28.addSuppressed(var27);
                  }

                  throw var28;
               }

               br.close();
               String body = response.toString();
               LOGGER.info("SVR:Vulners response bytes={}", body.length());
               JSONObject json = JSONObject.fromObject(body);
               if (!json.optString("result").equals("OK")) {
                  LOGGER.warn("SVR:Vulners result not OK");
                  return null;
               } else {
                  JSONObject data = json.optJSONObject("data");
                  if (data == null) {
                     return null;
                  } else {
                     JSONArray documents = data.optJSONArray("search");
                     if (documents != null && documents.size() != 0) {
                        LOGGER.info("SVR:Vulners found {} vulnerability records", documents.size());
                        LOGGER.info("SVR:Vulners status=200 items={} ms={} software={} version={}", documents.size(), responseTime, software, version);
                        EnrichmentResult result = new EnrichmentResult();
                        result.setSource("Vulners");
                        List<EnrichmentResult.VulnerabilityInfo> vulns = new ArrayList();

                        for(int i = 0; i < Math.min(documents.size(), 50); ++i) {
                           JSONObject doc = documents.getJSONObject(i);
                           JSONObject source = doc.optJSONObject("_source");
                           if (source != null) {
                              EnrichmentResult.VulnerabilityInfo vuln = new EnrichmentResult.VulnerabilityInfo();
                              vuln.setCveId(source.optString("id", "N/A"));
                              vuln.setTitle(source.optString("title", source.optString("description", "N/A")));
                              vuln.setDescription(source.optString("description", ""));
                              JSONObject cvssObj = source.optJSONObject("cvss");
                              if (cvssObj != null) {
                                 vuln.setCvssScore(cvssObj.optDouble("score", (double)0.0F));
                              } else {
                                 vuln.setCvssScore(source.optDouble("cvss", (double)0.0F));
                              }

                              vulns.add(vuln);
                           }
                        }

                        result.setVulnerabilities(vulns);
                        return result;
                     } else {
                        LOGGER.info("SVR:Vulners found 0 vulnerability records");
                        LOGGER.info("SVR:Vulners status=200 items=0 ms={} software={} version={}", responseTime, software, version);
                        return null;
                     }
                  }
               }
            }
         } catch (Exception e) {
            LOGGER.error("SVR:Vulners query failed: {}", e.getMessage(), e);
            return null;
         }
      } else {
         LOGGER.warn("SVR:Vulners API key is required - register free at vulners.com");
         return null;
      }
   }
}
