package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.featureextraction.probe.result.CNTypeProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.extension.SubjectAlternativeNameConfig;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class CNTypeProbe extends SimpleProbe{

    private final DirectoryStringChoiceType directoryStringChoiceType;
    private final boolean canSanBeAbsentEntity;

    public CNTypeProbe(DirectoryStringChoiceType directoryStringChoiceType, boolean canSanBeAbsentEntity) {
        this.directoryStringChoiceType = directoryStringChoiceType;
        this.canSanBeAbsentEntity = canSanBeAbsentEntity;
    }

    @Override
    protected X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig =
                X509CertificateConfigUtil.createBasicConfig(2);
        x509CertificateChainConfig
                .getEntityCertificateConfig()
                .setDefaultDirectoryStringType(directoryStringChoiceType);

        if (canSanBeAbsentEntity) {
            SubjectAlternativeNameConfig config =
                    (SubjectAlternativeNameConfig)
                            X509CertificateConfigUtil.getExtensionConfig(
                                    x509CertificateChainConfig.getEntityCertificateConfig(), X509ExtensionType.SUBJECT_ALTERNATIVE_NAME);
            config.setPresent(false);
        }

        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new CNTypeProbeResult(directoryStringChoiceType, verifierResult.isValid());
    }
}
