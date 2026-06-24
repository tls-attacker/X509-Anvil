package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.featureextraction.probe.result.BasicConstraintsPathLenResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class BasicConstraintsPathLenProbe extends SimpleProbe {

    private final int pathLen;

    public BasicConstraintsPathLenProbe(int pathLen) {
        this.pathLen = pathLen;
    }

    @Override
    protected X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig =
                X509CertificateConfigUtil.createBasicConfig(3);
        BasicConstraintsConfig config =
                (BasicConstraintsConfig)
                        X509CertificateConfigUtil.getExtensionConfig(
                                x509CertificateChainConfig.getIntermediateConfig(0), X509ExtensionType.BASIC_CONSTRAINTS);
        config.setPathLenConstraint(pathLen);
        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new BasicConstraintsPathLenResult(verifierResult.isValid(), pathLen);
    }
}
