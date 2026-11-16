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
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import org.junit.jupiter.api.TestInfo;

public class RsaSignatureDigestOidTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "signature-7c91a6e204")
    public void rsaMd2SignatureDigestOidIncorrectEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.MD2_WITH_RSA_ENCRYPTION);
                            config.setDifferentRsaDigestAlgorithmOid(new ObjectIdentifier("1.2.3.4.5.6.7.8"));
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "signature-b38d20f671")
    public void rsaMd2SignatureDigestOidIncorrectIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.MD2_WITH_RSA_ENCRYPTION);
                            config.setDifferentRsaDigestAlgorithmOid(new ObjectIdentifier("1.2.3.4.5.6.7.8"));
                        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "signature-04e7c9a152")
    public void rsaMd5SignatureDigestOidIncorrectEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.MD5_WITH_RSA_ENCRYPTION);
                            config.setDifferentRsaDigestAlgorithmOid(new ObjectIdentifier("1.2.3.4.5.6.7.8"));
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "signature-d65b8190af")
    public void rsaMd5SignatureDigestOidIncorrectIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.MD5_WITH_RSA_ENCRYPTION);
                            config.setDifferentRsaDigestAlgorithmOid(new ObjectIdentifier("1.2.3.4.5.6.7.8"));
                        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "signature-28f4a0c963")
    public void rsaSha1SignatureDigestOidIncorrectEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION);
                            config.setDifferentRsaDigestAlgorithmOid(new ObjectIdentifier("1.2.3.4.5.6.7.8"));
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "signature-e9037b5d14")
    public void rsaSha1SignatureDigestOidIncorrectIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION);
                            config.setDifferentRsaDigestAlgorithmOid(new ObjectIdentifier("1.2.3.4.5.6.7.8"));
                        }, testInfo);
    }
}
