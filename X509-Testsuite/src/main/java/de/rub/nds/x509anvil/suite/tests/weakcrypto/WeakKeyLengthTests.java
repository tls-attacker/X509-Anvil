package de.rub.nds.x509anvil.suite.tests.weakcrypto;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.CachedKeyPairGenerator;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.suite.tests.util.Constraints;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.security.NoSuchAlgorithmException;

public class WeakKeyLengthTests extends X509AnvilTest {

    @AnvilTest(description = "Check whether verifier accepts signatures computed with a 512-bit RSA key")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @ValueConstraint(identifier = "inter0.key_type", clazz = Constraints.class, method = "allowRsa")
    @ValueConstraint(identifier = "inter0.hash_algorithm", clazz = Constraints.class, method = "restrictHashForRsa512")    //Sha-512/SHA-384 digests are too big for RSA-512
    public void weak512BitRsaKey(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException, NoSuchAlgorithmException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        certificateChainConfig.getIntermediateConfig(0).setKeyPair(
                CachedKeyPairGenerator.retrieveKeyPair("weak-rsa-key", "RSA", 512));
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @AnvilTest(description = "Check whether verifier accepts signatures computed with a 1024-bit RSA key")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @ValueConstraint(identifier = "inter0.key_type", clazz = Constraints.class, method = "allowRsa")
    public void weak1024BitRsaKey(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException, NoSuchAlgorithmException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        certificateChainConfig.getIntermediateConfig(0).setKeyPair(
                CachedKeyPairGenerator.retrieveKeyPair("weak-rsa-key", "RSA", 1024));
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @AnvilTest(description = "Check whether verifier accepts signatures computed with a 1024-bit DSA key")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @ValueConstraint(identifier = "inter0.key_type", clazz = Constraints.class, method = "allowDsa")
    public void weak1024BitDsaKey(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException, NoSuchAlgorithmException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        certificateChainConfig.getIntermediateConfig(0).setKeyPair(
                CachedKeyPairGenerator.retrieveKeyPair("weak-dsa-key", "DSA", 1024));
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
