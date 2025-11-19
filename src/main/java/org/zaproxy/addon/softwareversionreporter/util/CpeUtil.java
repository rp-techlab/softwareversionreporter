package org.zaproxy.addon.softwareversionreporter.util;

public class CpeUtil {
   public static String build(String vendor, String product, String version) {
      String v = norm(vendor);
      String p = norm(product);
      String ver = version != null && !version.isBlank() ? version : "*";
      return "cpe:2.3:a:" + v + ":" + p + ":" + ver + ":*:*:*:*:*:*:*";
   }

   public static Parts parse(String cpe) {
      if (cpe != null && cpe.startsWith("cpe:2.3:")) {
         String[] s = cpe.split(":");
         return s.length >= 6 ? new Parts(s[3], s[4], s[5]) : new Parts((String)null, (String)null, (String)null);
      } else {
         return new Parts((String)null, (String)null, (String)null);
      }
   }

   private static String norm(String s) {
      return s != null && !s.isBlank() ? s.toLowerCase() : "*";
   }

   public static final class Parts {
      public final String vendor;
      public final String product;
      public final String version;

      public Parts(String vendor, String product, String version) {
         this.vendor = vendor;
         this.product = product;
         this.version = version;
      }
   }
}
