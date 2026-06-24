package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.featureextraction.probe.result.CNTypeProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;

public class CNTypeProbe extends SimpleProbe{

    private final DirectoryStringChoiceType directoryStringChoiceType;

    public CNTypeProbe(DirectoryStringChoiceType directoryStringChoiceType) {
        this.directoryStringChoiceType = directoryStringChoiceType;
    }

    @Override
    protected X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig =
                X509CertificateConfigUtil.createBasicConfig(2);
        x509CertificateChainConfig
                .getEntityCertificateConfig()
                .setDefaultDirectoryStringType(directoryStringChoiceType);
        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new CNTypeProbeResult(directoryStringChoiceType, verifierResult.isValid());
    }
}
