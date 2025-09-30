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

public class AuthorityKeyIdNotPresentTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-a2c84a2918")
    public void authKeyIdNotPresentEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier) config -> {
                    AuthorityKeyIdentifierConfig authorityKeyIdentifier =
                            (AuthorityKeyIdentifierConfig)
                                    X509CertificateConfigUtil.getExtensionConfig(
                                            config, X509ExtensionType.AUTHORITY_KEY_IDENTIFIER);
                    authorityKeyIdentifier.setPresent(false);
                });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-198c1c9f93")
    public void authKeyIdNotPresentIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier) config -> {
                    AuthorityKeyIdentifierConfig authorityKeyIdentifier =
                            (AuthorityKeyIdentifierConfig)
                                    X509CertificateConfigUtil.getExtensionConfig(
                                            config, X509ExtensionType.AUTHORITY_KEY_IDENTIFIER);
                    authorityKeyIdentifier.setPresent(false);
                });
    }
}
