package de.rub.nds.x509anvil.suite.tests.weakcrypto;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.key.CachedKeyPairGenerator;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import org.junit.jupiter.api.Assertions;

import java.security.NoSuchAlgorithmException;

public class WeakKeyLengthTests extends X509AnvilTest {

    @AnvilTest()
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @ValueConstraint(identifier = "inter0:key_type", method = "allowRsa")
    @ValueConstraint(identifier = "inter0:hash_algorithm", method = "restrictHashForRsa512")    //Sha-512/SHA-384 digests are too big for RSA-512
    public void weak512BitRsaKey(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException, NoSuchAlgorithmException {
        // TODO: Needs new config stuff for keys
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        CachedKeyPairGenerator.generateNewKeys(new SignatureHashAlgorithmKeyLengthPair(X509SignatureAlgorithm.RSASSA_PSS, 512), certificateChainConfig.getLastSigningConfig(), "inter0");
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @AnvilTest()
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @ValueConstraint(identifier = "inter0:key_type", method = "allowRsa")
    public void weak1024BitRsaKey(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException, NoSuchAlgorithmException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        CachedKeyPairGenerator.generateNewKeys(new SignatureHashAlgorithmKeyLengthPair(X509SignatureAlgorithm.RSASSA_PSS, 1024), certificateChainConfig.getLastSigningConfig(), "inter0");
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @AnvilTest()
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @ValueConstraint(identifier = "inter0:key_type", method = "allowDsa")
    public void weak1024BitDsaKey(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException, NoSuchAlgorithmException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        CachedKeyPairGenerator.generateNewKeys(new SignatureHashAlgorithmKeyLengthPair(X509SignatureAlgorithm.DSA_WITH_SHA256, 1024), certificateChainConfig.getLastSigningConfig(), "inter0");
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
