/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.basicfields.subjectpkinfo.algorithm;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.framework.x509.key.CachedKeyPairGenerator;
import de.rub.nds.x509attacker.config.extension.KeyUsageConfig;

import org.junit.jupiter.api.TestInfo;

public class DhAlgorithmParametersTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-subjectpki-algorithm-79c21ea40b")
    public void subjectPublicKeyInfoDhSeedWithoutPgenCounterEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            CachedKeyPairGenerator.generateDhKeys(2048, config, "entity");
                            config.setUseDhX942Parameters(true);
                            config.setIncludeDhValidationParameters(true);
                            config.setIncludeDhValidationParameterSeed(true);
                            config.setIncludeDhValidationParameterPgenCounter(false);
                            config.getExtensions().removeIf(extension -> extension instanceof KeyUsageConfig);
                        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-subjectpki-algorithm-b8520d6fc3")
    public void subjectPublicKeyInfoDhPgenCounterWithoutSeedEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            CachedKeyPairGenerator.generateDhKeys(2048, config, "entity");
                            config.setUseDhX942Parameters(true);
                            config.setIncludeDhValidationParameters(true);
                            config.setIncludeDhValidationParameterSeed(false);
                            config.setIncludeDhValidationParameterPgenCounter(true);
                            config.getExtensions().removeIf(extension -> extension instanceof KeyUsageConfig);
                        }, testInfo);
    }
}
