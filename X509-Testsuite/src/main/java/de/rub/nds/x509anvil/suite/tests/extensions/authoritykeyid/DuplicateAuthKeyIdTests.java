package de.rub.nds.x509anvil.suite.tests.extensions.authoritykeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.AuthorityKeyIdentifierConfig;
import de.rub.nds.x509attacker.config.extension.SubjectKeyIdentifierConfig;

public class DuplicateAuthKeyIdTests extends X509AnvilTest {

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-012f1b4bd0")
    public void duplicateIdenticalEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, config -> {
            AuthorityKeyIdentifierConfig authorityKeyIdentifier = new AuthorityKeyIdentifierConfig();
            authorityKeyIdentifier.setPresent(true);
            authorityKeyIdentifier.setKeyIdentifier(new byte[] {1, 2, 3});
            config.addExtensions(authorityKeyIdentifier);
            config.addExtensions(authorityKeyIdentifier);
            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
            newConfig.setPresent(true);
            newConfig.setKeyIdentifier(new byte[] {1,2,3});
            config.addExtensions(newConfig);
            config.setIncludeExtensions(true);
        });
    }


    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength = 4)
    @AnvilTest(id = "extension-ff7cdd6926")
    public void duplicateIdenticalIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, config -> {
            AuthorityKeyIdentifierConfig authorityKeyIdentifier = new AuthorityKeyIdentifierConfig();
            authorityKeyIdentifier.setPresent(true);
            authorityKeyIdentifier.setKeyIdentifier(new byte[] {1, 2, 3});
            config.addExtensions(authorityKeyIdentifier);
            config.addExtensions(authorityKeyIdentifier);
            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
            newConfig.setPresent(true);
            newConfig.setKeyIdentifier(new byte[] {1,2,3});
            config.addExtensions(newConfig);
            config.setIncludeExtensions(true);
        });
    }


    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-4a5dd1e00a")
    public void duplicateDifferentEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, config -> {
            AuthorityKeyIdentifierConfig authorityKeyIdentifier = new AuthorityKeyIdentifierConfig();
            authorityKeyIdentifier.setPresent(true);
            authorityKeyIdentifier.setKeyIdentifier(new byte[] {1, 2, 3});
            config.addExtensions(authorityKeyIdentifier);

            AuthorityKeyIdentifierConfig differentConfig = new AuthorityKeyIdentifierConfig();
            differentConfig.setPresent(true);
            differentConfig.setKeyIdentifier(new byte[] {2, 3, 4});
            config.addExtensions(differentConfig);

            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
            newConfig.setPresent(true);
            newConfig.setKeyIdentifier(new byte[] {1,2,3});
            config.addExtensions(newConfig);
            config.setIncludeExtensions(true);
        });
    }


    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength = 4)
    @AnvilTest(id = "extension-3b0f420c2c")
    public void duplicateDifferentIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, config -> {
            AuthorityKeyIdentifierConfig authorityKeyIdentifier = new AuthorityKeyIdentifierConfig();
            authorityKeyIdentifier.setPresent(true);
            authorityKeyIdentifier.setKeyIdentifier(new byte[] {1, 2, 3});
            config.addExtensions(authorityKeyIdentifier);

            AuthorityKeyIdentifierConfig differentConfig = new AuthorityKeyIdentifierConfig();
            differentConfig.setPresent(true);
            differentConfig.setKeyIdentifier(new byte[] {2, 3, 4});
            config.addExtensions(differentConfig);

            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
            newConfig.setPresent(true);
            newConfig.setKeyIdentifier(new byte[] {1,2,3});
            config.addExtensions(newConfig);
            config.setIncludeExtensions(true);
        });
    }
}
