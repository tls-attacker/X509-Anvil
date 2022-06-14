package de.rub.nds.x509anvil.x509.config.model;

public abstract class ExtensionConfig {
    private boolean critical;

    public ExtensionConfig(boolean critical) {
        this.critical = critical;
    }

    public ExtensionConfig() {}

    public boolean isCritical() {
        return critical;
    }

    public void setCritical(boolean critical) {
        this.critical = critical;
    }
}
