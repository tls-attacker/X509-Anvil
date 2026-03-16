/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.weakcrypto;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.junit.jupiter.api.TestInfo;

public class WeakHashAlgorithmTests extends X509AnvilTest {

    @AnvilTest(id = "weakcrypto-8cce4bf80f")
    @ChainLength(minLength = 3)
    public void weakHashMd2(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> config.amendSignatureAlgorithm(HashAlgorithm.MD2), testInfo);
    }

    @AnvilTest(id = "weakcrypto-fa9ccc9dfa")
    @ChainLength(minLength = 3)
    public void weakHashMd4(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> config.amendSignatureAlgorithm(HashAlgorithm.MD4), testInfo);
    }

    @AnvilTest(id = "weakcrypto-0499c0a19c")
    @ChainLength(minLength = 3)
    public void weakHashMd5(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> config.amendSignatureAlgorithm(HashAlgorithm.MD5), testInfo);
    }

    @AnvilTest(id = "weakcrypto-dbc5ebe60a")
    @ChainLength(minLength = 3)
    public void weakHashSha1(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> config.amendSignatureAlgorithm(HashAlgorithm.SHA1), testInfo);
    }
}
