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
import de.rub.nds.asn1.constants.TimeAccurracy;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import org.joda.time.DateTime;

public class UtcTimeWithoutSecondsTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:not_before")
    @AnvilTest(id = "basic-f898ad6553")
    public void notBeforeEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotBefore(new DateTime(2001, 1, 1, 0, 0));
                            config.setDefaultNotBeforeEncoding(ValidityEncoding.UTC);
                            config.setNotBeforeAccurracy(TimeAccurracy.MINUTES);
                        });
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:not_before")
    @AnvilTest(id = "basic-963d221c48")
    public void notBeforeIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotBefore(new DateTime(2001, 1, 1, 0, 0));
                            config.setDefaultNotBeforeEncoding(ValidityEncoding.UTC);
                            config.setNotBeforeAccurracy(TimeAccurracy.MINUTES);
                        });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:not_after")
    @AnvilTest(id = "basic-88ec7bd824")
    public void notAfterEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotAfter(new DateTime(2030, 1, 1, 0, 0));
                            config.setDefaultNotAfterEncoding(ValidityEncoding.UTC);
                            config.setNotAfterAccurracy(TimeAccurracy.MINUTES);
                        });
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:not_after")
    @AnvilTest(id = "basic-cfa169c84e")
    public void notAfterIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotAfter(new DateTime(2030, 1, 1, 0, 0));
                            config.setDefaultNotAfterEncoding(ValidityEncoding.UTC);
                            config.setNotAfterAccurracy(TimeAccurracy.MINUTES);
                        });
    }
}
