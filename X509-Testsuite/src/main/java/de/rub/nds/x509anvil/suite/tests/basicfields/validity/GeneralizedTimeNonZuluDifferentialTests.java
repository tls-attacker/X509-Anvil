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

/**
 * These tests set the notBefore and notAfter fields to non Zulu (GMT) values by setting them to
 * local time.
 */
public class GeneralizedTimeNonZuluDifferentialTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:not_before")
    @AnvilTest(id = "basic-21f3acf036")
    public void notBeforeEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotBefore(new DateTime(2020, 1, 1, 0, 0, 0));
                            config.setDefaultNotBeforeEncoding(
                                    ValidityEncoding.GENERALIZED_TIME_DIFFERENTIAL);
                            config.setTimezoneOffsetInMinutes(60);
                        });
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:not_before")
    @AnvilTest(id = "basic-4b8345d5e1")
    public void notBeforeIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotBefore(new DateTime(2020, 1, 1, 0, 0, 0));
                            config.setDefaultNotBeforeEncoding(
                                    ValidityEncoding.GENERALIZED_TIME_DIFFERENTIAL);
                            config.setTimezoneOffsetInMinutes(60);
                        });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:not_after")
    @AnvilTest(id = "basic-b2548936e9")
    public void notAfterEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotAfter(new DateTime(2050, 1, 1, 0, 0, 0));
                            config.setDefaultNotBeforeEncoding(
                                    ValidityEncoding.GENERALIZED_TIME_DIFFERENTIAL);
                            config.setTimezoneOffsetInMinutes(60);
                        });
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:not_after")
    @AnvilTest(id = "basic-797cfb720a")
    public void notAfterIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotAfter(new DateTime(2050, 1, 1, 0, 0, 0));
                            config.setDefaultNotBeforeEncoding(
                                    ValidityEncoding.GENERALIZED_TIME_DIFFERENTIAL);
                            config.setTimezoneOffsetInMinutes(60);
                        });
    }
}
