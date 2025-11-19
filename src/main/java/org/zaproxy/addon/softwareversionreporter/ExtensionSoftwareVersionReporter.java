package org.zaproxy.addon.softwareversionreporter;

import java.util.Collections;
import java.util.List;
import javax.swing.SwingWorker;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

public class ExtensionSoftwareVersionReporter extends ExtensionAdaptor {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionSoftwareVersionReporter.class);

    public static final String NAME = "ExtensionSoftwareVersionReporter";
    protected static final String PREFIX = "softwareversionreporter";

    private static ExtensionSoftwareVersionReporter instance;

    private SoftwareVersionReporterParam param;
    private VulnerabilityEnrichmentService enrichmentService;

    private volatile List currentRules = Collections.emptyList();
    private volatile String lastRulesError = null;
    private volatile boolean rulesLoading = false;
    private final Object rulesLock = new Object();

    public ExtensionSoftwareVersionReporter() {
        super("ExtensionSoftwareVersionReporter");
        this.setI18nPrefix(PREFIX);
        instance = this;
    }

    public static ExtensionSoftwareVersionReporter getInstance() {
        return instance;
    }

    @Override
    public void init() {
        super.init();
        this.param = new SoftwareVersionReporterParam();
        this.enrichmentService = new VulnerabilityEnrichmentService(this.param);
        this.reloadRulesAsync(null);
    }

    @Override
    public void hook(ExtensionHook hook) {
        super.hook(hook);
        if (this.getView() != null) {
            hook.getHookView()
                    .addOptionPanel(
                            new org.zaproxy.addon.softwareversionreporter.ui.SoftwareVersionReporterOptionsPanel(
                                    this));
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("softwareversionreporter.desc");
    }

    public SoftwareVersionReporterParam getParam() {
        return this.param;
    }

    public VulnerabilityEnrichmentService getEnrichmentService() {
        return this.enrichmentService;
    }

    public List getCurrentRules() {
        synchronized (this.rulesLock) {
            return this.currentRules;
        }
    }

    public String getLastRulesError() {
        synchronized (this.rulesLock) {
            return this.lastRulesError;
        }
    }

    public boolean isRulesLoading() {
        synchronized (this.rulesLock) {
            return this.rulesLoading;
        }
    }

    public void reloadRulesAsync(final Runnable onDone) {
        synchronized (this.rulesLock) {
            if (this.rulesLoading) {
                return;
            }
            this.rulesLoading = true;
        }

        new SwingWorker() {
            @Override
            protected List doInBackground() {
                try {
                    List rules = (new DetectionRuleLoader()).load();
                    synchronized (ExtensionSoftwareVersionReporter.this.rulesLock) {
                        ExtensionSoftwareVersionReporter.this.currentRules = rules;
                        ExtensionSoftwareVersionReporter.this.lastRulesError = null;
                    }
                    return rules;
                } catch (Exception e) {
                    synchronized (ExtensionSoftwareVersionReporter.this.rulesLock) {
                        ExtensionSoftwareVersionReporter.this.currentRules = Collections.emptyList();
                        ExtensionSoftwareVersionReporter.this.lastRulesError = e.getMessage();
                    }
                    return Collections.emptyList();
                }
            }

            @Override
            protected void done() {
                synchronized (ExtensionSoftwareVersionReporter.this.rulesLock) {
                    ExtensionSoftwareVersionReporter.this.rulesLoading = false;
                }
                if (onDone != null) {
                    onDone.run();
                }
            }
        }.execute();
    }
}
