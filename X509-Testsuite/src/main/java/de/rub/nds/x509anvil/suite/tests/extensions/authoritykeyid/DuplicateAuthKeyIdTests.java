package de.rub.nds.x509anvil.suite.tests.extensions.authoritykeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.AuthorityKeyIdentifierConfig;
import de.rub.nds.x509attacker.config.extension.SubjectKeyIdentifierConfig;

public class DuplicateAuthKeyIdTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @AnvilTest(id = "extension-0aafd3e26f")
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


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @AnvilTest(id = "extension-0aafd3e26f")
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


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @AnvilTest(id = "extension-0aafd3e26f")
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


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @AnvilTest(id = "extension-0aafd3e26f")
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
