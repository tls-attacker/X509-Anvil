package de.rub.nds.x509anvil.suite.tests.extensions.subjectkeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
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

public class AuthKeyIdSubjectKeyIdMismatchTests extends X509AnvilTest {
    @Specification(document = "RFC 5280", section = "4.2.1.2. Subject Key Identifier",
            text = "In conforming CA certificates, the value of the subject key identifier MUST be the value placed in the key identifier " +
                    "field of the authority key identifier extension (Section 4.2.1.1) of certificates issued by the subject of this certificate.")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void keyIdMismatchEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, config -> {
            AuthorityKeyIdentifierConfig authorityKeyIdentifier = new AuthorityKeyIdentifierConfig();
            authorityKeyIdentifier.setPresent(true);
            authorityKeyIdentifier.setKeyIdentifier(new byte[] {1, 2, 3});
            config.addExtensions(authorityKeyIdentifier);
            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
            newConfig.setPresent(true);
            newConfig.setKeyIdentifier(new byte[] {2,3,4});
            config.addExtensions(newConfig);
            config.setIncludeExtensions(true);
        });
    }


    @Specification(document = "RFC 5280", section = "4.2.1.2. Subject Key Identifier",
            text = "In conforming CA certificates, the value of the subject key identifier MUST be the value placed in the key identifier " +
                    "field of the authority key identifier extension (Section 4.2.1.1) of certificates issued by the subject of this certificate.")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void keyIdMismatchIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, config -> {
            AuthorityKeyIdentifierConfig authorityKeyIdentifier = new AuthorityKeyIdentifierConfig();
            authorityKeyIdentifier.setPresent(true);
            authorityKeyIdentifier.setKeyIdentifier(new byte[] {1, 2, 3});
            config.addExtensions(authorityKeyIdentifier);
            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
            newConfig.setPresent(true);
            newConfig.setKeyIdentifier(new byte[] {2,3,4});
            config.addExtensions(newConfig);
            config.setIncludeExtensions(true);
        });
    }
}
