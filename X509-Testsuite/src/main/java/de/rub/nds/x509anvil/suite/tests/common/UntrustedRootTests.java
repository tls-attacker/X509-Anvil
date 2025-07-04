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
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.StaticRoot;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import java.util.ArrayList;
import java.util.List;

public class UntrustedRootTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "common-f15e7199ea")
    @StaticRoot(false)
    public void untrustedRootCertificate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertBooleanRoot(
                testRunner,
                false,
                config -> {
                    List<Pair<X500AttributeType, String>> subject =
                            new ArrayList<>(config.getSubject());
                    subject.set(
                            0,
                            new Pair<>(
                                    subject.get(0).getLeftElement(),
                                    subject.get(0).getRightElement() + " Untrusted"));
                    config.setSubject(subject);
                });
    }
}
