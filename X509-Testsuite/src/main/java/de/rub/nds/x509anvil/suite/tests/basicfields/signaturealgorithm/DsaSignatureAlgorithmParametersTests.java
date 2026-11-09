/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.basicfields.signaturealgorithm;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import org.junit.jupiter.api.TestInfo;

public class DsaSignatureAlgorithmParametersTests extends X509AnvilTest {

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:key_type")
    @AnvilTest(id = "basic-signaturealgorithm-5f0b81d3c7")
    public void dsaWithSha1SignatureAlgorithmParametersPresentEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.DSA_WITH_SHA1);
                            config.setIncludeSignatureAlgorithmParameters(true);
                        },
                (X509CertificateConfigModifier)
                        issuerConfig -> issuerConfig.setPublicKeyType(X509PublicKeyType.DSA), testInfo);
    }

    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "inter1:key_type")
    @AnvilTest(id = "basic-signaturealgorithm-a26d4e90b8")
    public void dsaWithSha1SignatureAlgorithmParametersPresentIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setSignatureAlgorithm(X509SignatureAlgorithm.DSA_WITH_SHA1);
                            config.setIncludeSignatureAlgorithmParameters(true);
                        },
                (X509CertificateConfigModifier)
                        issuerConfig -> issuerConfig.setPublicKeyType(X509PublicKeyType.DSA), testInfo);
    }
}
