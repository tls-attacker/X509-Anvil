/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.junit.jupiter.api.TestInfo;

public class PositiveTest extends X509AnvilTest {

    @ChainLength(minLength = 2, maxLength = 2)
    @AnvilTest(id = "common-positive-f4db514b76")
    public void positiveTest2(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertValid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            // No specific changes to config needed for this test, keeping the
                            // default valid case.
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "common-positive-f4db514b77")
    public void positiveTest3(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertValid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            // No specific changes to config needed for this test, keeping the
                            // default valid case.
                        }, testInfo);
    }

    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength =  4)
    @AnvilTest(id = "common-positive-f4db514b78")
    public void positiveTest4(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertValid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            // No specific changes to config needed for this test, keeping the
                            // default valid case.
                        }, testInfo);
    }
}
