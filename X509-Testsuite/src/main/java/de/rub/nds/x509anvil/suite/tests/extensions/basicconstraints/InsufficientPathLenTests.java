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
import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class InsufficientPathLenTests extends X509AnvilTest {

    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @IpmLimitations(
            identifiers =
                    "inter0:ext_basic_constraints_pathlen_constraint, inter0:ext_basic_constraints_pathlen_constraint_present")
    @AnvilTest(id = "extension-b88af2b7d6")
    public void insufficientPathLenChainLength4(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertBooleanFirstIntermediate(
                testRunner,
                false,
                config -> {
                    BasicConstraintsConfig basicConstraintsConfig =
                            (BasicConstraintsConfig)
                                    X509CertificateConfigUtil.getExtensionConfig(
                                            config, X509ExtensionType.BASIC_CONSTRAINTS);
                    basicConstraintsConfig.setPresent(true);
                    basicConstraintsConfig.setCa(true);
                    basicConstraintsConfig.setPathLenConstraint(0);
                    basicConstraintsConfig.setIncludeCA(DefaultEncodingRule.ENCODE);
                    basicConstraintsConfig.setIncludePathLenConstraint(DefaultEncodingRule.ENCODE);
                });
    }

    @ChainLength(minLength = 5, maxLength = 5, intermediateCertsModeled = 3)
    @IpmLimitations(
            identifiers =
                    "inter0:ext_basic_constraints_pathlen_constraint, inter0:ext_basic_constraints_pathlen_constraint_present")
    @AnvilTest(id = "extension-f4379eba22")
    public void insufficientPathLenChainLength5(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertBooleanFirstIntermediate(
                testRunner,
                false,
                config -> {
                    BasicConstraintsConfig basicConstraintsConfig =
                            (BasicConstraintsConfig)
                                    X509CertificateConfigUtil.getExtensionConfig(
                                            config, X509ExtensionType.BASIC_CONSTRAINTS);
                    basicConstraintsConfig.setPresent(true);
                    basicConstraintsConfig.setCa(true);
                    basicConstraintsConfig.setPathLenConstraint(1);
                    basicConstraintsConfig.setIncludeCA(DefaultEncodingRule.ENCODE);
                    basicConstraintsConfig.setIncludePathLenConstraint(DefaultEncodingRule.ENCODE);
                });
    }

    @ChainLength(minLength = 10, maxLength = 10, intermediateCertsModeled = 8)
    @IpmLimitations(
            identifiers =
                    "inter0:ext_basic_constraints_pathlen_constraint, inter0:ext_basic_constraints_pathlen_constraint_present")
    @AnvilTest(id = "extension-a4b5710704")
    public void insufficientPathLenChainLength10(X509VerifierRunner testRunner)
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
                            basicConstraintsConfig.setPresent(true);
                            basicConstraintsConfig.setCa(true);
                            basicConstraintsConfig.setPathLenConstraint(6);
                            basicConstraintsConfig.setIncludeCA(DefaultEncodingRule.ENCODE);
                            basicConstraintsConfig.setIncludePathLenConstraint(
                                    DefaultEncodingRule.ENCODE);
                        });
    }
}
