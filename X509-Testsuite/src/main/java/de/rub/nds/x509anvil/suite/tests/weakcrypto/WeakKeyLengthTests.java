package de.rub.nds.x509anvil.suite.tests.weakcrypto;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.constants.SignatureAndHashAlgorithmLengthPair;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.CachedKeyPairGenerator;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.security.NoSuchAlgorithmException;

public class WeakKeyLengthTests extends X509AnvilTest {

    @AnvilTest()
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @ValueConstraint(identifier = "inter0.key_type", method = "allowRsa")
    @ValueConstraint(identifier = "inter0.hash_algorithm", method = "restrictHashForRsa512")    //Sha-512/SHA-384 digests are too big for RSA-512
    public void weak512BitRsaKey(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException, NoSuchAlgorithmException {
        assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config -> {
            config.applyKeyPair(CachedKeyPairGenerator.generateNewKeys.retrieveKeyPair(SignatureAlgorithm.RSA_PKCS1, 512));
        });

        @AnvilTest()
        @SeverityLevel(Severity.CRITICAL)
        @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
        @ValueConstraint(identifier = "inter0.key_type", method = "allowRsa")
        public void weak1024BitRsaKey (ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws
        VerifierException, CertificateGeneratorException, NoSuchAlgorithmException
        {
            assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config -> {
                config.applyKeyPair(CachedKeyPairGenerator.generateNewKeys.retrieveKeyPair(SignatureAlgorithm.RSA_PKCS1, 1024));
            });


            @AnvilTest()
            @SeverityLevel(Severity.CRITICAL)
            @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
            @ValueConstraint(identifier = "inter0.key_type", method = "allowDsa")
            public void weak1024BitDsaKey (ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws
            VerifierException, CertificateGeneratorException, NoSuchAlgorithmException {
            assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config -> {
                config.applyKeyPair(CachedKeyPairGenerator.generateNewKeys.retrieveKeyPair(SignatureAlgorithm.DSA, 1024));
            });

        }
        }
    }
}