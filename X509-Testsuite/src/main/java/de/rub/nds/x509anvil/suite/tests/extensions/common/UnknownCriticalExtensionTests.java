/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.extensions.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.UnknownConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import org.junit.jupiter.api.TestInfo;

public class UnknownCriticalExtensionTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = {"entity:extensions_present"})
    @AnvilTest(id = "extension-d8772be424")
    public void unknownCriticalExtensionEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            UnknownConfig unknownConfig =
                                    new UnknownConfig(
                                            X509ExtensionType.UNKNOWN.getOid(), "unknownExtension");
                            unknownConfig.setCritical(true);
                            unknownConfig.setPresent(true);
                            unknownConfig.setContent(new byte[] {10, 11, 12});
                            config.addExtensions(unknownConfig);
                        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-14d5fe1bed")
    public void unknownCriticalExtensionIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            UnknownConfig unknownConfig =
                                    new UnknownConfig(
                                            X509ExtensionType.UNKNOWN.getOid(), "unknownExtension");
                            unknownConfig.setCritical(true);
                            unknownConfig.setPresent(true);
                            unknownConfig.setContent(new byte[] {10, 11, 12});
                            config.addExtensions(unknownConfig);
                        }, testInfo);
    }
}
