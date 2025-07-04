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

public class PositiveTest extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "common-f4db514b76")
    public void sampleTestCase(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertValid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            // No specific changes to config needed for this test, keeping the
                            // default valid case.
                        });
    }
}
