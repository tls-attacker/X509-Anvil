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
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.junit.jupiter.api.TestInfo;

public class EmptySignatureTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "signature-aee615f131")
    public void emptySignatureEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier) config -> config.setSignatureEmpty(true), testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "signature-0c864620d2")
    public void emptySignatureIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier) config -> config.setSignatureEmpty(true), testInfo);
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "signature-104b0eac54")
    public void nullSignatureRoot(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertBooleanRoot(testRunner, false, config -> config.setSignatureEmpty(true), testInfo);
    }
}
