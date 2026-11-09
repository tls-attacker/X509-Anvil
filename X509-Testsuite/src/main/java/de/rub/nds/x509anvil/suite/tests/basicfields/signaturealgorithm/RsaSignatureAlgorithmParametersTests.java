/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.basicfields.signaturealgorithm;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import org.junit.jupiter.api.TestInfo;

public class RsaSignatureAlgorithmParametersTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-signaturealgorithm-3a4d9c70b2")
    public void md2WithRsaSignatureAlgorithmParametersOmittedEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.MD2_WITH_RSA_ENCRYPTION);
                            config.setIncludeSignatureAlgorithmParameters(false);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-signaturealgorithm-8c12fa650d")
    public void md2WithRsaSignatureAlgorithmParametersOmittedIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.MD2_WITH_RSA_ENCRYPTION);
                            config.setIncludeSignatureAlgorithmParameters(false);
                        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-signaturealgorithm-69eb4f238a")
    public void md5WithRsaSignatureAlgorithmParametersOmittedEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.MD5_WITH_RSA_ENCRYPTION);
                            config.setIncludeSignatureAlgorithmParameters(false);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-signaturealgorithm-b543d720ec")
    public void md5WithRsaSignatureAlgorithmParametersOmittedIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.MD5_WITH_RSA_ENCRYPTION);
                            config.setIncludeSignatureAlgorithmParameters(false);
                        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-signaturealgorithm-d17a630be4")
    public void sha1WithRsaSignatureAlgorithmParametersOmittedEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION);
                            config.setIncludeSignatureAlgorithmParameters(false);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-signaturealgorithm-4f92ce18a6")
    public void sha1WithRsaSignatureAlgorithmParametersOmittedIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION);
                            config.setIncludeSignatureAlgorithmParameters(false);
                        }, testInfo);
    }
}
