package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.SANAbsentResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.extension.SubjectAlternativeNameConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class SANAbsentProbe extends SimpleProbe{
    @Override
    protected X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig =
                X509CertificateConfigUtil.createBasicConfig(2);
        SubjectAlternativeNameConfig config =
                (SubjectAlternativeNameConfig)
                        X509CertificateConfigUtil.getExtensionConfig(
                                x509CertificateChainConfig.getEntityCertificateConfig(), X509ExtensionType.SUBJECT_ALTERNATIVE_NAME);
        config.setPresent(false);
        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new SANAbsentResult(verifierResult.isValid());
    }
}
