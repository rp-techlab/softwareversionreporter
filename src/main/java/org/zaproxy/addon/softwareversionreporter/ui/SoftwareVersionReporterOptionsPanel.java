package org.zaproxy.addon.softwareversionreporter.ui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.InputStream;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.softwareversionreporter.ExtensionSoftwareVersionReporter;
import org.zaproxy.addon.softwareversionreporter.SoftwareVersionReporterParam;

public class SoftwareVersionReporterOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;
    private final ExtensionSoftwareVersionReporter extension;
    private JCheckBox enableEnrichmentCheckBox;
    private JCheckBox enrichWhenNoVersionCheckBox;
    private JComboBox<String> apiProviderComboBox;
    private JPasswordField nvdApiKeyField;
    private JPasswordField vulnersApiKeyField;
    private JPasswordField vuldbApiKeyField;
    private JButton loadRulesButton;
    private JButton reloadRulesButton;
    private JButton exportRulesButton;
    private JLabel rulesStatusLabel;

    public SoftwareVersionReporterOptionsPanel(ExtensionSoftwareVersionReporter extension) {
        this.extension = extension;
        this.setName(Constant.messages.getString("softwareversionreporter.options.title"));
        this.setLayout(new GridBagLayout());
        this.buildUI();
    }

    private void buildUI() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = 17;
        gbc.insets = new Insets(4, 8, 4, 8);
        gbc.fill = 2;
        int row = 0;
        gbc.gridx = 0;
        gbc.gridy = row++;
        gbc.gridwidth = 2;
        this.enableEnrichmentCheckBox = new JCheckBox("Enable vulnerability enrichment");
        this.add(this.enableEnrichmentCheckBox, gbc);
        gbc.gridy = row++;
        this.enrichWhenNoVersionCheckBox = new JCheckBox("Enrich even when no version found");
        this.add(this.enrichWhenNoVersionCheckBox, gbc);
        gbc.gridwidth = 1;
        gbc.gridy = row;
        this.add(new JLabel("API Provider:"), gbc);
        gbc.gridx = 1;
        this.apiProviderComboBox = new JComboBox(new String[]{"nvd", "vulners", "vuldb"});
        this.add(this.apiProviderComboBox, gbc);
        ++row;
        gbc.gridx = 0;
        gbc.gridy = row;
        this.add(new JLabel("NVD API Key:"), gbc);
        gbc.gridx = 1;
        this.nvdApiKeyField = new JPasswordField(20);
        this.add(this.nvdApiKeyField, gbc);
        ++row;
        gbc.gridx = 0;
        gbc.gridy = row;
        this.add(new JLabel("Vulners API Key:"), gbc);
        gbc.gridx = 1;
        this.vulnersApiKeyField = new JPasswordField(20);
        this.add(this.vulnersApiKeyField, gbc);
        ++row;
        gbc.gridx = 0;
        gbc.gridy = row;
        this.add(new JLabel("VulDB API Key:"), gbc);
        gbc.gridx = 1;
        this.vuldbApiKeyField = new JPasswordField(20);
        this.add(this.vuldbApiKeyField, gbc);
        ++row;
        gbc.gridx = 0;
        gbc.gridy = row++;
        gbc.gridwidth = 2;
        this.add(this.createRulesPanel(), gbc);
    }

    @Override
    public void initParam(Object obj) {
        SoftwareVersionReporterParam param = this.extension.getParam();
        this.enableEnrichmentCheckBox.setSelected(param.isEnrichmentEnabled());
        this.enrichWhenNoVersionCheckBox.setSelected(param.isEnrichWhenNoVersion());
        this.apiProviderComboBox.setSelectedItem(param.getApiProvider());
        this.nvdApiKeyField.setText(param.getNvdApiKey());
        this.vulnersApiKeyField.setText(param.getVulnersApiKey());
        this.vuldbApiKeyField.setText(param.getVuldbApiKey());
        this.updateRulesStatus();
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        SoftwareVersionReporterParam param = this.extension.getParam();
        param.setEnrichmentEnabled(this.enableEnrichmentCheckBox.isSelected());
        param.setEnrichWhenNoVersion(this.enrichWhenNoVersionCheckBox.isSelected());
        param.setApiProvider((String)this.apiProviderComboBox.getSelectedItem());
        param.setNvdApiKey(new String(this.nvdApiKeyField.getPassword()));
        param.setVulnersApiKey(new String(this.vulnersApiKeyField.getPassword()));
        param.setVuldbApiKey(new String(this.vuldbApiKeyField.getPassword()));
    }

    @Override
    public String getHelpIndex() {
        return null;
    }

    private JPanel createRulesPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Detection Rules"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 4, 2, 4);
        gbc.anchor = 17;
        gbc.gridx = 0;
        gbc.gridy = 0;
        this.loadRulesButton = new JButton(new AbstractAction("Load Rules from File...") {
            @Override
            public void actionPerformed(ActionEvent e) {
                SoftwareVersionReporterOptionsPanel.this.loadRulesFromFile();
            }
        });
        panel.add(this.loadRulesButton, gbc);
        gbc.gridx = 1;
        this.reloadRulesButton = new JButton(new AbstractAction("Reload Default Rules") {
            @Override
            public void actionPerformed(ActionEvent e) {
                SoftwareVersionReporterOptionsPanel.this.reloadDefaultRules();
            }
        });
        panel.add(this.reloadRulesButton, gbc);
        gbc.gridx = 2;
        this.exportRulesButton = new JButton(new AbstractAction("Export Rules...") {
            @Override
            public void actionPerformed(ActionEvent e) {
                SoftwareVersionReporterOptionsPanel.this.exportRules();
            }
        });
        panel.add(this.exportRulesButton, gbc);
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 3;
        gbc.fill = 2;
        this.rulesStatusLabel = new JLabel("");
        panel.add(this.rulesStatusLabel, gbc);
        return panel;
    }

    private void updateRulesStatus() {
        List rules = this.extension.getCurrentRules();
        String err = this.extension.getLastRulesError();
        if (this.extension.isRulesLoading()) {
            this.rulesStatusLabel.setText("Loading rules...");
            this.rulesStatusLabel.setForeground(Color.BLUE);
        } else if (err != null) {
            this.rulesStatusLabel.setText("Error: " + err);
            this.rulesStatusLabel.setForeground(Color.RED);
        } else if (rules != null && !rules.isEmpty()) {
            this.rulesStatusLabel.setText(rules.size() + " rules loaded");
            this.rulesStatusLabel.setForeground(new Color(0, 128, 0));
        } else {
            this.rulesStatusLabel.setText("No rules loaded");
            this.rulesStatusLabel.setForeground(Color.ORANGE);
        }
    }

    private void loadRulesFromFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("TSV Files", new String[]{"tsv"}));
        if (chooser.showOpenDialog(this) == 0) {
            Path src = chooser.getSelectedFile().toPath();

            try {
                Path destDir = Path.of(System.getProperty("user.home"), ".ZAP", "softwareversionreporter");
                Files.createDirectories(destDir);
                Path dest = destDir.resolve("detection-rules.tsv");
                Files.copy(src, dest, new CopyOption[]{StandardCopyOption.REPLACE_EXISTING});
                this.extension.reloadRulesAsync(() -> {
                    SwingUtilities.invokeLater(this::updateRulesStatus);
                });
                JOptionPane.showMessageDialog(
                        this,
                        "Rules file loaded and reloaded successfully.",
                        "Success",
                        1);
            } catch (Exception var5) {
                JOptionPane.showMessageDialog(
                        this,
                        "Failed to load rules file: " + var5.getMessage(),
                        "Error",
                        0);
            }
        }
    }

    private void reloadDefaultRules() {
        this.extension.reloadRulesAsync(() -> {
            SwingUtilities.invokeLater(() -> {
                this.updateRulesStatus();
                JOptionPane.showMessageDialog(
                        this,
                        "Default rules reloaded from built-in resource.",
                        "Success",
                        1);
            });
        });
    }

    private void exportRules() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("TSV Files", new String[]{"tsv"}));
        chooser.setSelectedFile(new java.io.File("detection-rules.tsv"));
        if (chooser.showSaveDialog(this) == 0) {
            try {
                InputStream in = this.getClass().getResourceAsStream("/org/zaproxy/addon/softwareversionreporter/detection-rules.tsv");
                Throwable var3 = null;

                try {
                    if (in == null) {
                        JOptionPane.showMessageDialog(
                                this,
                                "Default rules resource not found.",
                                "Error",
                                0);
                        return;
                    }

                    Path dest = chooser.getSelectedFile().toPath();
                    Files.copy(in, dest, new CopyOption[]{StandardCopyOption.REPLACE_EXISTING});
                    JOptionPane.showMessageDialog(
                            this,
                            "Rules exported to " + dest,
                            "Success",
                            1);
                } catch (Throwable var13) {
                    var3 = var13;
                    throw var13;
                } finally {
                    if (in != null) {
                        if (var3 != null) {
                            try {
                                in.close();
                            } catch (Throwable var12) {
                                var3.addSuppressed(var12);
                            }
                        } else {
                            in.close();
                        }
                    }
                }
            } catch (Exception var15) {
                JOptionPane.showMessageDialog(
                        this,
                        "Failed to export rules: " + var15.getMessage(),
                        "Error",
                        0);
            }
        }
    }

    private static class ProgressComponent extends JComponent {

        private boolean animating = false;
        private int frame = 0;

        ProgressComponent() {
        }

        void start() {
            this.animating = true;
            this.frame = 0;
        }

        void stop() {
            this.animating = false;
            this.repaint();
        }

        @Override
        public Dimension getPreferredSize() {
            return new Dimension(200, 20);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (this.animating) {
                g.setColor(Color.BLUE);
                int w = this.getWidth();
                int x = this.frame % w;
                g.fillRect(x, 0, 20, this.getHeight());
                ++this.frame;
                this.repaint();
            }
        }
    }
}
