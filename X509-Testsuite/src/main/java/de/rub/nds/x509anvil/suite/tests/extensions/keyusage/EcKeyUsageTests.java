/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under the Apache License, Version 2.0
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
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import org.junit.jupiter.api.TestInfo;

public class EcKeyUsageTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = { "entity:extensions_present", "entity:ext_key_usage_additional" })
    @AnvilTest(id = "extension-ku-98c73b6e21")
    public void ecKeyUsageEncipherOnlyAndDecipherOnlyEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA);
                            KeyUsageConfig keyUsageConfig = (KeyUsageConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.KEY_USAGE);
                            keyUsageConfig.setKeyEncipherment(false);
                            keyUsageConfig.setKeyAgreement(true);
                            keyUsageConfig.setEncipherOnly(true);
                            keyUsageConfig.setDecipherOnly(true);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    // "entity:extensions_present" limitation not necessary, since Intermediate always contains extensions
    @IpmLimitations(identifiers = { "entity:key_type", "inter0:ext_key_usage_additional" })
    @AnvilTest(id = "extension-ku-2ba914f7d0")
    public void ecKeyUsageEncipherOnlyAndDecipherOnlyIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        entityConfig -> {
                            entityConfig.setSignatureAlgorithm(X509SignatureAlgorithm.ECDSA_WITH_SHA256);
                        },
                (X509CertificateConfigModifier)
                        config -> {
                            config.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA);
                            KeyUsageConfig keyUsageConfig = (KeyUsageConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.KEY_USAGE);
                            keyUsageConfig.setKeyAgreement(true);
                            keyUsageConfig.setEncipherOnly(true);
                            keyUsageConfig.setDecipherOnly(true);
                        }, testInfo);
    }
}
