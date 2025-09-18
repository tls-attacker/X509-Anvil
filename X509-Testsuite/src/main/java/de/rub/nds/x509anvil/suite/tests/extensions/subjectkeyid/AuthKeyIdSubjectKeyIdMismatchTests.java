/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.extensions.subjectkeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.AuthorityKeyIdentifierConfig;
import de.rub.nds.x509attacker.config.extension.SubjectKeyIdentifierConfig;

public class AuthKeyIdSubjectKeyIdMismatchTests extends X509AnvilTest {

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-a71fd6a6dc")
    public void keyIdMismatchEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                config -> {
                    AuthorityKeyIdentifierConfig authorityKeyIdentifier =
                            new AuthorityKeyIdentifierConfig();
                    authorityKeyIdentifier.setPresent(true);
                    authorityKeyIdentifier.setKeyIdentifier(new byte[] {1, 2, 3});
                    config.addExtensions(authorityKeyIdentifier);
                    config.setIncludeExtensions(true);
                },
                (X509CertificateConfigModifier)
                        config -> {
                            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
                            newConfig.setPresent(true);
                            newConfig.setKeyIdentifier(new byte[] {2, 3, 4});
                            config.addExtensions(newConfig);
                            config.setIncludeExtensions(true);
                        });
    }

    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength = 4)
    @AnvilTest(id = "extension-0ff7547245")
    public void keyIdMismatchIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                config -> {
                    AuthorityKeyIdentifierConfig authorityKeyIdentifier =
                            new AuthorityKeyIdentifierConfig();
                    authorityKeyIdentifier.setPresent(true);
                    authorityKeyIdentifier.setKeyIdentifier(new byte[] {1, 2, 3});
                    config.addExtensions(authorityKeyIdentifier);
                    config.setIncludeExtensions(true);
                },
                (X509CertificateConfigModifier)
                        config -> {
                            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
                            newConfig.setPresent(true);
                            newConfig.setKeyIdentifier(new byte[] {2, 3, 4});
                            config.addExtensions(newConfig);
                            config.setIncludeExtensions(true);
                        });
    }
}
