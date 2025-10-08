/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.extensions.authoritykeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.AuthorityKeyIdentifierConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class MissingKeyIdTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-190349e95d")
    public void missingKeyIdentifierEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            AuthorityKeyIdentifierConfig authorityKeyIdentifier =
                                    (AuthorityKeyIdentifierConfig)
                                            X509CertificateConfigUtil.getExtensionConfig(
                                                    config, X509ExtensionType.AUTHORITY_KEY_IDENTIFIER);
                            authorityKeyIdentifier.setKeyIdentifier(null);
                        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-9e241be2f9")
    public void missingKeyIdentifierIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            AuthorityKeyIdentifierConfig authorityKeyIdentifier =
                                    (AuthorityKeyIdentifierConfig)
                                            X509CertificateConfigUtil.getExtensionConfig(
                                                    config, X509ExtensionType.AUTHORITY_KEY_IDENTIFIER);
                            authorityKeyIdentifier.setKeyIdentifier(null);
                        });
    }
}
