package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.SignatureAlgorithmProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.security.KeyPair;

public class SignatureAlgorithmProbe extends SimpleProbe {
    private final SignatureAlgorithm signatureAlgorithm;

    public SignatureAlgorithmProbe(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    protected X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig = X509CertificateConfigUtil.createBasicConfig(3);
        X509CertificateConfig ca = x509CertificateChainConfig.getIntermediateCertificateConfigs().get(0);
        ca.setKeyType(signatureAlgorithm.getKeyType());
        ca.setHashAlgorithm(signatureAlgorithm.getHashAlgorithm());
        KeyPair keyPair = X509CertificateConfigUtil.generateKeyPair(signatureAlgorithm.getKeyType(), ca.getCertificateName());
        ca.setKeyPair(keyPair);
        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new SignatureAlgorithmProbeResult(signatureAlgorithm, verifierResult.isValid());
    }
}
