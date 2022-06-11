package de.rub.nds.x509anvil.x509.config.model;

public abstract class Extension {
    private boolean critical;

    public Extension(boolean critical) {
        this.critical = critical;
    }

    public Extension() {}

    public boolean isCritical() {
        return critical;
    }

    public void setCritical(boolean critical) {
        this.critical = critical;
    }
}
