package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ExtensionsPresentResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;

public class ExtensionsPresentProbe extends SimpleProbe{
    @Override
    protected X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig =
                X509CertificateConfigUtil.createBasicConfig(2);
        x509CertificateChainConfig.getEntityCertificateConfig().setIncludeExtensions(false);
        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new ExtensionsPresentResult(verifierResult.isValid());
    }
}
