package org.zaproxy.addon.softwareversionreporter;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DetectionRuleLoader {

    private static final Logger LOGGER = LogManager.getLogger(DetectionRuleLoader.class);
    private static final String CLASSPATH_RULES = "/org/zaproxy/addon/softwareversionreporter/detection-rules.tsv";
    private static final String USER_RULE_PATH = System.getProperty("user.home") +
        File.separator + ".ZAP" + File.separator + "softwareversionreporter" + File.separator + "detection-rules.tsv";

    public List<DetectionRule> load() {
        List<DetectionRule> rules = null;
        // Try user file first
        File userFile = new File(USER_RULE_PATH);
        if (userFile.exists() && userFile.isFile()) {
            try (InputStream is = new FileInputStream(userFile);
                 BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                rules = loadFromReader(br);
                LOGGER.info("Loaded {} detection rules from user file {}", rules.size(), USER_RULE_PATH);
            } catch (Exception e) {
                LOGGER.error("Failed to load user-provided rules from {}: {}", USER_RULE_PATH, e.getMessage());
                // fallback below
            }
        }
        // Fallback to classpath resource
        if (rules == null || rules.isEmpty()) {
            try (InputStream is = getClass().getResourceAsStream(CLASSPATH_RULES);
                 BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                rules = loadFromReader(br);
                LOGGER.info("Loaded {} detection rules from classpath", rules.size());
            } catch (Exception e) {
                LOGGER.error("Failed to load detection rules from classpath: {}", e.getMessage());
                return Collections.emptyList();
            }
        }
        return Collections.unmodifiableList(rules);
    }

    private List<DetectionRule> loadFromReader(BufferedReader reader) throws Exception {
        List<DetectionRule> rules = new ArrayList<>();
        String line;
        boolean firstLine = true;
        int lineNum = 0;
        while ((line = reader.readLine()) != null) {
            ++lineNum;
            if (firstLine) {
                firstLine = false; // skip header
                continue;
            }
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] parts = line.split("\\t");
            if (parts.length >= 5) {
                rules.add(new DetectionRule(
                    parts[0],   // regex
                    parts[1],   // type
                    parts[2],   // software
                    parts[3],   // vendor
                    parts[4]    // product
                ));
            } else {
                LOGGER.warn("Skipping malformed rule at {}: '{}'", lineNum, line);
            }
        }
        return rules;
    }

    public static class DetectionRule {
        private final String regex;
        private final Pattern pattern;
        private final String type;
        private final String software;
        private final String vendor;
        private final String product;
        public DetectionRule(String regex, String type, String software, String vendor, String product) {
            this.regex = regex;
            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            this.type = type;
            this.software = software;
            this.vendor = vendor;
            this.product = product;
        }
        public String getSoftware()       { return software; }
        public String getType()           { return type; }
        public Pattern getPattern()       { return pattern; }
        public String getVendor()         { return vendor; }
        public String getProduct()        { return product; }
        public String getRegex()          { return regex; }
    }
}
