/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.basicfields.uniqueidentifiers;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.junit.jupiter.api.TestInfo;

import java.math.BigInteger;

public class IssuerUniqueIdInV1CertTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:version")
    @AnvilTest(id = "basic-4cfe12547b")
    public void issuerUniqueIdPresentInV1Entity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setIncludeIssuerUniqueId(true);
                            config.setDefaultIssuerUniqueId(new byte[] {0x0, 0x1, 0x2, 0x3});
                            config.setVersion(BigInteger.valueOf(0));
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:version")
    @AnvilTest(id = "basic-adc3be6001")
    public void issuerUniqueIdPresentInV1Intermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setIncludeIssuerUniqueId(true);
                            config.setDefaultIssuerUniqueId(new byte[] {0x0, 0x1, 0x2, 0x3});
                            config.setVersion(BigInteger.valueOf(0));
                        }, testInfo);
    }
}
