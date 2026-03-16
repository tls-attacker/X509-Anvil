/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.basicfields.issuer;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.junit.jupiter.api.TestInfo;

public class IssuerNotPresentTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-3d37c180b5")
    public void noIssuerEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier) config -> config.setIncludeIssuer(false), testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-3502b37055")
    public void noIssuerIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier) config -> config.setIncludeIssuer(false), testInfo);
    }
}
