package de.rub.nds.x509anvil.suite.tests.weakcrypto;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.key.CachedKeyPairGenerator;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import org.junit.jupiter.api.Assertions;

public class WeakKeyLengthTests extends X509AnvilTest {

    @ChainLength(minLength = 3)
    @AnvilTest(id = "weakcrypto-5521f8be14")
    public void weak512BitRsaKey(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        CachedKeyPairGenerator.generateNewKeys(new SignatureHashAlgorithmKeyLengthPair(X509SignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION, 512), certificateChainConfig.getLastSigningConfig(), "inter0");
        certificateChainConfig.getEntityCertificateConfig().setSignatureAlgorithm(X509SignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION);
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "weakcrypto-448bf60b34")
    public void weak1024BitRsaKey(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        CachedKeyPairGenerator.generateNewKeys(new SignatureHashAlgorithmKeyLengthPair(X509SignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION, 1024), certificateChainConfig.getLastSigningConfig(), "inter0");
        certificateChainConfig.getEntityCertificateConfig().setSignatureAlgorithm(X509SignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION);
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "weakcrypto-8246133e52")
    public void weak1024BitDsaKey(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        CachedKeyPairGenerator.generateNewKeys(new SignatureHashAlgorithmKeyLengthPair(X509SignatureAlgorithm.DSA_WITH_SHA256, 1024), certificateChainConfig.getLastSigningConfig(), "inter0");
        certificateChainConfig.getEntityCertificateConfig().setSignatureAlgorithm(X509SignatureAlgorithm.DSA_WITH_SHA256);
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
