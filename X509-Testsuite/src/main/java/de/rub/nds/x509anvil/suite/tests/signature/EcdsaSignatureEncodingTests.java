/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.signature;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import org.junit.jupiter.api.TestInfo;

public class EcdsaSignatureEncodingTests extends X509AnvilTest {

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:key_type")
    @AnvilTest(id = "signature-c560a8d213")
    public void ecdsaSignatureSequenceWrongTypeEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.ECDSA_WITH_SHA1);
                            config.setIncludeSignatureAlgorithmParameters(false);
                            config.setDsaEcdsaSignatureSequenceTag(0x04);
                        },
                (X509CertificateConfigModifier)
                        issuerConfig -> issuerConfig.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA), testInfo);
    }

    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "inter1:key_type")
    @AnvilTest(id = "signature-4f18bc709e")
    public void ecdsaSignatureSequenceWrongTypeIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.ECDSA_WITH_SHA1);
                            config.setIncludeSignatureAlgorithmParameters(false);
                            config.setDsaEcdsaSignatureSequenceTag(0x04);
                        },
                (X509CertificateConfigModifier)
                        issuerConfig -> issuerConfig.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA), testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:key_type")
    @AnvilTest(id = "signature-a307d9e461")
    public void ecdsaSignatureRWrongTypeEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.ECDSA_WITH_SHA1);
                            config.setIncludeSignatureAlgorithmParameters(false);
                            config.setDsaEcdsaSignatureRTag(0x04);
                        },
                (X509CertificateConfigModifier)
                        issuerConfig -> issuerConfig.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA), testInfo);
    }

    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "inter1:key_type")
    @AnvilTest(id = "signature-8b6e02ca94")
    public void ecdsaSignatureRWrongTypeIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.ECDSA_WITH_SHA1);
                            config.setIncludeSignatureAlgorithmParameters(false);
                            config.setDsaEcdsaSignatureRTag(0x04);
                        },
                (X509CertificateConfigModifier)
                        issuerConfig -> issuerConfig.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA), testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:key_type")
    @AnvilTest(id = "signature-d42c7f018b")
    public void ecdsaSignatureSWrongTypeEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.ECDSA_WITH_SHA1);
                            config.setIncludeSignatureAlgorithmParameters(false);
                            config.setDsaEcdsaSignatureSTag(0x04);
                        },
                (X509CertificateConfigModifier)
                        issuerConfig -> issuerConfig.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA), testInfo);
    }

    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "inter1:key_type")
    @AnvilTest(id = "signature-5e9a31d670")
    public void ecdsaSignatureSWrongTypeIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.ECDSA_WITH_SHA1);
                            config.setIncludeSignatureAlgorithmParameters(false);
                            config.setDsaEcdsaSignatureSTag(0x04);
                        },
                (X509CertificateConfigModifier)
                        issuerConfig -> issuerConfig.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA), testInfo);
    }
}
