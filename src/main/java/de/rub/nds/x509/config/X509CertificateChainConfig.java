package de.rub.nds.x509.config;

import java.util.ArrayList;
import java.util.List;

public class X509CertificateChainConfig {
    private List<X509CertificateConfig> certificateConfigs = new ArrayList<>();  // Index 0 is root

    public void addCertificateConfig(X509CertificateConfig certificateConfig) {
        this.certificateConfigs.add(certificateConfig);
    }

    public X509CertificateConfig getRootConfig() {
        return this.certificateConfigs.get(0);
    }

    public X509CertificateConfig getEntityConfig() {
        return this.certificateConfigs.get(this.certificateConfigs.size() - 1);
    }

    public List<X509CertificateConfig> getCertificateConfigs() {
        return certificateConfigs;
    }

    public void setCertificateConfigs(List<X509CertificateConfig> certificateConfigs) {
        this.certificateConfigs = certificateConfigs;
    }
}
