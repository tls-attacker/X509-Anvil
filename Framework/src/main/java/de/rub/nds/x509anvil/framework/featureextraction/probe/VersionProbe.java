package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.x509.X509CertificateUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

public class VersionProbe extends Probe {
    private final int version;

    public VersionProbe(VerifierAdapter verifierAdapter, int version) {
        super(verifierAdapter);
        this.version = version;
    }

    @Override
    public ProbeResult executeProbe() {
        return null;
    }

    public X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig = X509CertificateUtil.createBasicConfig(2);
        x509CertificateChainConfig.getEntityCertificateConfig().setVersion(version);
        return x509CertificateChainConfig;
    }
}
