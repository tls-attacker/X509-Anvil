package de.rub.nds.x509anvil.suite.tests.extensions.authoritykeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.AuthorityKeyIdentifierConfig;
import de.rub.nds.x509attacker.config.extension.SubjectKeyIdentifierConfig;

public class CriticalAuthorityKeyIdTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.1. Authority Key Identifier", text = "Conforming CAs MUST mark this extension as non-critical.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @AnvilTest()
    public void criticalAuthorityKeyIdEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, config -> {
            AuthorityKeyIdentifierConfig authorityKeyIdentifier = new AuthorityKeyIdentifierConfig();
            authorityKeyIdentifier.setPresent(true);
            authorityKeyIdentifier.setCritical(true);
            authorityKeyIdentifier.setKeyIdentifier(new byte[] {1, 2, 3});
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

    @Specification(document = "RFC 5280", section = "4.2.1.1. Authority Key Identifier", text = "Conforming CAs MUST mark this extension as non-critical.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @AnvilTest()
    public void criticalAuthorityKeyIdIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, config -> {
            AuthorityKeyIdentifierConfig authorityKeyIdentifier = new AuthorityKeyIdentifierConfig();
            authorityKeyIdentifier.setPresent(true);
            authorityKeyIdentifier.setCritical(true);
            authorityKeyIdentifier.setKeyIdentifier(new byte[] {1, 2, 3});
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
}
