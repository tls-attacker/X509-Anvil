/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.extensions.basicconstraints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import org.junit.jupiter.api.TestInfo;

import java.util.ArrayList;
import java.util.List;

public class DuplicateBasicConstraintsTests extends X509AnvilTest {

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-5427239f8e")
    public void duplicateIdenticalIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            BasicConstraintsConfig basicConstraintsConfig =
                                    (BasicConstraintsConfig)
                                            X509CertificateConfigUtil.getExtensionConfig(
                                                    config, X509ExtensionType.BASIC_CONSTRAINTS);
                            config.addExtensions(basicConstraintsConfig);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:ext_basic_constraints_ca")
    @AnvilTest(id = "extension-027e0728ed")
    public void duplicateDifferentIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            BasicConstraintsConfig basicConstraintsConfig =
                                    (BasicConstraintsConfig)
                                            X509CertificateConfigUtil.getExtensionConfig(
                                                    config, X509ExtensionType.BASIC_CONSTRAINTS);
                            BasicConstraintsConfig newConfig = new BasicConstraintsConfig();
                            newConfig.setCa(!basicConstraintsConfig.isCa());
                            newConfig.setPresent(true);
                            config.addExtensions(newConfig);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:ext_basic_constraints_ca")
    @AnvilTest(id = "extension-027e0728ff")
    public void duplicateDifferentOrderIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            BasicConstraintsConfig basicConstraintsConfig =
                                    (BasicConstraintsConfig)
                                            X509CertificateConfigUtil.getExtensionConfig(
                                                    config, X509ExtensionType.BASIC_CONSTRAINTS);
                            BasicConstraintsConfig newConfig = new BasicConstraintsConfig();
                            newConfig.setCa(!basicConstraintsConfig.isCa());
                            newConfig.setPresent(true);

                            List<ExtensionConfig> extensions = new ArrayList<>(config.getExtensions());
                            extensions.add(0, newConfig);
                            config.setExtensions(extensions);
                        }, testInfo);
    }
}
