/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.KeyUsageConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class KeyUsageOverflowTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = { "entity:extensions_present", "entity:ext_key_usage_additional" })
    @AnvilTest(id = "extension-53e2e2bb36")
    public void keyUsageOverflowAppend1Entity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            KeyUsageConfig keyUsageConfig =
                                    (KeyUsageConfig)
                                            X509CertificateConfigUtil.getExtensionConfig(
                                                    config, X509ExtensionType.KEY_USAGE);
                            keyUsageConfig.setPresent(true);

                            keyUsageConfig.setDigitalSignature(true);
                            keyUsageConfig.setKeyAgreement(false);
                            keyUsageConfig.setKeyCertSign(false);
                            keyUsageConfig.setKeyEncipherment(false);

                            keyUsageConfig.setNonRepudiation(true);
                            keyUsageConfig.setOverflowInvalidation(true);
                            keyUsageConfig.setOverflowWithOne(true);
                            config.setIncludeExtensions(true);
                        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-7042e82768")
    @IpmLimitations(identifiers = "inter0:ext_key_usage_additional")
    public void keyUsageOverflowAppend1Intermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            KeyUsageConfig keyUsageConfig =
                                    (KeyUsageConfig)
                                            X509CertificateConfigUtil.getExtensionConfig(
                                                    config, X509ExtensionType.KEY_USAGE);
                            keyUsageConfig.setPresent(true);

                            keyUsageConfig.setDigitalSignature(true);
                            keyUsageConfig.setKeyAgreement(true);
                            keyUsageConfig.setKeyCertSign(true);
                            keyUsageConfig.setKeyEncipherment(true);

                            keyUsageConfig.setNonRepudiation(true);
                            keyUsageConfig.setOverflowInvalidation(true);
                            keyUsageConfig.setOverflowWithOne(true);
                            config.setIncludeExtensions(true);
                        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-c88ac06a56")
    @IpmLimitations(identifiers = { "entity:extensions_present", "entity:ext_key_usage_additional" })
    public void keyUsageOverflowAppend0Entity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            KeyUsageConfig keyUsageConfig =
                                    (KeyUsageConfig)
                                            X509CertificateConfigUtil.getExtensionConfig(
                                                    config, X509ExtensionType.KEY_USAGE);
                            keyUsageConfig.setPresent(true);

                            keyUsageConfig.setDigitalSignature(true);
                            keyUsageConfig.setKeyAgreement(false);
                            keyUsageConfig.setKeyCertSign(false);
                            keyUsageConfig.setKeyEncipherment(false);

                            keyUsageConfig.setNonRepudiation(true);
                            keyUsageConfig.setOverflowInvalidation(true);
                            keyUsageConfig.setOverflowWithOne(false);
                            config.setIncludeExtensions(true);
                        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-a51284dc4b")
    @IpmLimitations(identifiers = "inter0:ext_key_usage_additional")
    public void keyUsageOverflowAppend0Intermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            KeyUsageConfig keyUsageConfig =
                                    (KeyUsageConfig)
                                            X509CertificateConfigUtil.getExtensionConfig(
                                                    config, X509ExtensionType.KEY_USAGE);
                            keyUsageConfig.setPresent(true);

                            keyUsageConfig.setDigitalSignature(true);
                            keyUsageConfig.setKeyAgreement(false);
                            keyUsageConfig.setKeyCertSign(false);
                            keyUsageConfig.setKeyEncipherment(false);

                            keyUsageConfig.setNonRepudiation(true);
                            keyUsageConfig.setOverflowInvalidation(true);
                            keyUsageConfig.setOverflowWithOne(false);
                            config.setIncludeExtensions(true);
                        });
    }
}
