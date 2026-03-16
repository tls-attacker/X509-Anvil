/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.basicfields.validity;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import org.joda.time.DateTime;
import org.junit.jupiter.api.TestInfo;

public class ExpiredTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:not_after")
    @AnvilTest(id = "basic-7d768e9cc6")
    public void expiredUtcEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotAfter(new DateTime(2020, 1, 1, 0, 0, 0));
                            config.setDefaultNotAfterEncoding(ValidityEncoding.UTC);
                        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:not_after")
    @AnvilTest(id = "basic-b71262c3ab")
    public void expiredGeneralizedEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotAfter(new DateTime(2020, 1, 1, 0, 0, 0));
                            config.setDefaultNotAfterEncoding(
                                    ValidityEncoding.GENERALIZED_TIME_UTC);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:not_after")
    @AnvilTest(id = "basic-a00de3717c")
    public void expiredUtcIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotAfter(new DateTime(2001, 1, 1, 0, 0, 0));
                            config.setDefaultNotAfterEncoding(ValidityEncoding.UTC);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:not_after")
    @AnvilTest(id = "basic-fd5f30ce88")
    public void expiredGeneralizedIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotAfter(new DateTime(2020, 1, 1, 0, 0, 0));
                            config.setDefaultNotAfterEncoding(
                                    ValidityEncoding.GENERALIZED_TIME_UTC);
                        }, testInfo);
    }
}
