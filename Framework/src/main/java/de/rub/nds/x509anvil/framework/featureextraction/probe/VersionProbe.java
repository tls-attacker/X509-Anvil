package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.VersionProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.X509CertificateUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;

public class VersionProbe extends SimpleProbe {
    private final int version;

    public VersionProbe(int version) {
        this.version = version;
    }

    @Override
    public X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig = X509CertificateUtil.createBasicConfig(2);
        x509CertificateChainConfig.getEntityCertificateConfig().setVersion(version);
        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new VersionProbeResult(version, verifierResult.isValid());
    }
}
