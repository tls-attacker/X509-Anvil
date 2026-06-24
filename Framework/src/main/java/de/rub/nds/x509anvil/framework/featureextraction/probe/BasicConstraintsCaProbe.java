package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.featureextraction.probe.result.BasicConstraintsCaResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class BasicConstraintsCaProbe extends SimpleProbe{
    @Override
    protected X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig =
                X509CertificateConfigUtil.createBasicConfig(2);
        BasicConstraintsConfig config =
                (BasicConstraintsConfig)
                        X509CertificateConfigUtil.getExtensionConfig(
                                x509CertificateChainConfig.getEntityCertificateConfig(), X509ExtensionType.BASIC_CONSTRAINTS);
        config.setCa(true);
        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new BasicConstraintsCaResult(verifierResult.isValid());
    }
}
