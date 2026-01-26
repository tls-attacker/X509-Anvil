/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.basicfields.tbssignature;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;
import org.junit.jupiter.api.TestInfo;

public class TbsSignatureMismatchTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:key_type")
    @AnvilTest(id = "basic-3e2fbb009f")
    public void tbsSignatureDoesntMatchAlgorithmEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setDifferentSignatureAlgorithmOid(
                                    TestUtils.getNonMatchingAlgorithmOid(
                                                    config.getSignatureAlgorithm())
                                            .getSignatureAndHashAlgorithm()
                                            .getOid());
                            config.setSignatureTbsCertOidDifferent(true);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:key_type")
    @AnvilTest(id = "basic-eec58410b3")
    public void tbsSignatureDoesntMatchAlgorithmIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setDifferentSignatureAlgorithmOid(
                                    TestUtils.getNonMatchingAlgorithmOid(
                                                    config.getSignatureAlgorithm())
                                            .getSignatureAndHashAlgorithm()
                                            .getOid());
                            config.setSignatureTbsCertOidDifferent(true);
                        }, testInfo);
    }
}
