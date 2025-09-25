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

public class DuplicateKeyUsageTests extends X509AnvilTest {

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-3e4c7f3e62")
    @IpmLimitations(identifiers = "inter0:ext_key_usage_additional")
    public void duplicateIdenticalIntermediate(X509VerifierRunner testRunner)
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
                            config.addExtensions(keyUsageConfig);
                        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-44d01aed5a")
    @IpmLimitations(identifiers = "inter0:ext_key_usage_additional")
    public void duplicateDifferentIntermediate(X509VerifierRunner testRunner)
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
                            KeyUsageConfig newConfig = new KeyUsageConfig();
                            newConfig.setPresent(true);
                            newConfig.setDataEncipherment(!keyUsageConfig.isDataEncipherment());
                            config.addExtensions(newConfig);
                        });
    }
}
