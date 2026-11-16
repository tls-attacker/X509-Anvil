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
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import org.junit.jupiter.api.TestInfo;

public class EcPublicKeyAlgorithmOidTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-subjectpki-algorithm-6a19c8e042")
    public void subjectPublicKeyInfoEcAlgorithmOidIncorrectEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA);
                            config.setDifferentSubjectPublicKeyAlgorithmOid(new ObjectIdentifier("1.2.3.4.5.6.7.8"));
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:key_type")
    @AnvilTest(id = "basic-subjectpki-algorithm-f427b0d913")
    public void subjectPublicKeyInfoEcAlgorithmOidIncorrectIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        entityConfig -> {
                            entityConfig.setSignatureAlgorithm(X509SignatureAlgorithm.ECDSA_WITH_SHA256);
                        },
                (X509CertificateConfigModifier)
                        config -> {
                            config.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA);
                            config.setDifferentSubjectPublicKeyAlgorithmOid(new ObjectIdentifier("1.2.3.4.5.6.7.8"));
                        }, testInfo);
    }
}
