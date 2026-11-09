/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.basicfields.subjectpkinfo.algorithm;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;

import org.junit.jupiter.api.TestInfo;

public class RsaPublicKeyEncodingTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-subjectpki-algorithm-74a9e2c061")
    public void subjectPublicKeyInfoRsaPublicKeyEncodedAsOctetStringEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setPublicKeyType(X509PublicKeyType.RSA);
                            config.setEncodePublicKeyAsOctetString(true);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:key_type")
    @AnvilTest(id = "basic-subjectpki-algorithm-c805f1b39d")
    public void subjectPublicKeyInfoRsaPublicKeyEncodedAsOctetStringIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setPublicKeyType(X509PublicKeyType.RSA);
                            config.setEncodePublicKeyAsOctetString(true);
                        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-subjectpki-algorithm-2f63a8d017")
    public void subjectPublicKeyInfoRsaModulusEncodedAsOctetStringEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setPublicKeyType(X509PublicKeyType.RSA);
                            config.setEncodeRsaModulusAsOctetString(true);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:key_type")
    @AnvilTest(id = "basic-subjectpki-algorithm-9b04e72ca6")
    public void subjectPublicKeyInfoRsaModulusEncodedAsOctetStringIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setPublicKeyType(X509PublicKeyType.RSA);
                            config.setEncodeRsaModulusAsOctetString(true);
                        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-subjectpki-algorithm-e18c5294ab")
    public void subjectPublicKeyInfoRsaPublicExponentEncodedAsOctetStringEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setPublicKeyType(X509PublicKeyType.RSA);
                            config.setEncodeRsaPublicExponentAsOctetString(true);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:key_type")
    @AnvilTest(id = "basic-subjectpki-algorithm-65d3b0f892")
    public void subjectPublicKeyInfoRsaPublicExponentEncodedAsOctetStringIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setPublicKeyType(X509PublicKeyType.RSA);
                            config.setEncodeRsaPublicExponentAsOctetString(true);
                        }, testInfo);
    }
}
