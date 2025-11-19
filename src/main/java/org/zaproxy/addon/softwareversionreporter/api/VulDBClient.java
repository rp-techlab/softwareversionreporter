package org.zaproxy.addon.softwareversionreporter.api;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
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

public class VulDBClient {
   private static final Logger LOGGER = LogManager.getLogger(VulDBClient.class);
   private static final String API_BASE = "https://vuldb.com/?api";
   private String apiKey;

   public VulDBClient(String apiKey) {
      this.apiKey = apiKey;
   }

   public EnrichmentResult query(String software, String version, String vendor, String product) {
      if (this.apiKey != null && !this.apiKey.trim().isEmpty()) {
         long start = System.currentTimeMillis();

         try {
            String searchQuery = String.format("%s %s", software, version);
            String postData = String.format("apikey=%s&search=%s", URLEncoder.encode(this.apiKey, "UTF-8"), URLEncoder.encode(searchQuery, "UTF-8"));
            LOGGER.info("SVR:VulDB starting query software={} version={} search={}", software, version, searchQuery);
            URL url = new URL("https://vuldb.com/?api");
            HttpURLConnection conn = (HttpURLConnection)url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            OutputStream os = conn.getOutputStream();

            try {
               byte[] input = postData.getBytes("UTF-8");
               os.write(input, 0, input.length);
            } catch (Throwable var36) {
               if (os != null) {
                  try {
                     os.close();
                  } catch (Throwable var35) {
                     var36.addSuppressed(var35);
                  }
               }

               throw var36;
            }

            if (os != null) {
               os.close();
            }

            int status = conn.getResponseCode();
            long responseTime = System.currentTimeMillis() - start;
            LOGGER.info("SVR:VulDB HTTP response status={} ms={}", status, responseTime);
            if (status != 200) {
               LOGGER.warn("SVR:VulDB error status={}", status);
               return null;
            } else {
               StringBuilder response = new StringBuilder();
               BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));

               String line;
               try {
                  while((line = br.readLine()) != null) {
                     response.append(line);
                  }
               } catch (Throwable var37) {
                  try {
                     br.close();
                  } catch (Throwable var34) {
                     var37.addSuppressed(var34);
                  }

                  throw var37;
               }

               br.close();
               String body = response.toString();
               LOGGER.info("SVR:VulDB response bytes={}", body.length());
               JSONObject json = JSONObject.fromObject(body);
               JSONObject responseObj = json.optJSONObject("response");
               if (responseObj != null) {
                  int apiStatus = responseObj.optInt("status", 0);
                  int items = responseObj.optInt("items", 0);
                  int remaining = responseObj.optInt("remaining", -1);
                  LOGGER.info("SVR:VulDB API status={} items={} remaining={}", apiStatus, items, remaining);
                  if (apiStatus != 200) {
                     LOGGER.warn("SVR:VulDB API error status={}", apiStatus);
                     return null;
                  }
               }

               JSONArray results = json.optJSONArray("result");
               if (results != null && results.size() != 0) {
                  LOGGER.info("SVR:VulDB status=200 items={} ms={} vendor={} product={} version={}", results.size(), responseTime, vendor, product, version);
                  EnrichmentResult result = new EnrichmentResult();
                  result.setSource("VulDB");
                  List<EnrichmentResult.VulnerabilityInfo> vulns = new ArrayList();

                  for(int i = 0; i < results.size(); ++i) {
                     JSONObject item = results.getJSONObject(i);
                     JSONObject entry = item.optJSONObject("entry");
                     if (entry != null) {
                        EnrichmentResult.VulnerabilityInfo info = new EnrichmentResult.VulnerabilityInfo();
                        info.setTitle(entry.optString("title", "N/A"));
                        JSONObject source = item.optJSONObject("source");
                        if (source != null) {
                           JSONObject cve = source.optJSONObject("cve");
                           if (cve != null) {
                              info.setCveId(cve.optString("id", ""));
                           }
                        }

                        if (info.getCveId() == null || info.getCveId().isEmpty()) {
                           info.setCveId("VulDB-" + entry.optString("id", "N/A"));
                        }

                        JSONObject vulnerability = item.optJSONObject("vulnerability");
                        if (vulnerability != null) {
                           JSONObject risk = vulnerability.optJSONObject("risk");
                           if (risk != null) {
                              String riskName = risk.optString("name", "");
                              int riskValue = risk.optInt("value", 0);
                              double cvssScore = (double)0.0F;
                              if (riskValue > 0) {
                                 cvssScore = (double)riskValue * (double)3.0F;
                              } else {
                                 switch (riskName.toLowerCase()) {
                                    case "low" -> cvssScore = (double)3.0F;
                                    case "medium" -> cvssScore = (double)6.0F;
                                    case "high" -> cvssScore = (double)8.0F;
                                    case "critical" -> cvssScore = (double)9.5F;
                                 }
                              }

                              info.setCvssScore(cvssScore);
                           }
                        }

                        vulns.add(info);
                     }
                  }

                  result.setVulnerabilities(vulns);
                  return result;
               } else {
                  LOGGER.info("SVR:VulDB status=200 items=0 ms={} vendor={} product={} version={}", responseTime, vendor, product, version);
                  return null;
               }
            }
         } catch (Exception e) {
            LOGGER.error("SVR:VulDB query failed: {}", e.getMessage(), e);
            return null;
         }
      } else {
         LOGGER.warn("SVR:VulDB API key is required");
         return null;
      }
   }
}
