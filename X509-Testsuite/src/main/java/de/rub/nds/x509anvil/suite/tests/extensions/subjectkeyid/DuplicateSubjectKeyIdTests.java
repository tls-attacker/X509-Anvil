package de.rub.nds.x509anvil.suite.tests.extensions.subjectkeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.SubjectKeyIdentifierConfig;

public class DuplicateSubjectKeyIdTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-ddb7cadc32")
    public void duplicateIdenticalEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
            newConfig.setPresent(true);
            newConfig.setKeyIdentifier(new byte[] {1, 2, 3, 4, 5});
            config.addExtensions(newConfig);
            config.addExtensions(newConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-ad98d1b6ce")
    public void duplicateIdenticalIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
            newConfig.setPresent(true);
            newConfig.setKeyIdentifier(new byte[] {1, 2, 3, 4, 5});
            config.addExtensions(newConfig);
            config.addExtensions(newConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-8fc40ac4e1")
    public void duplicateDifferentEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
            newConfig.setPresent(true);
            newConfig.setKeyIdentifier(new byte[] {1, 2, 3, 4, 5});
            config.addExtensions(newConfig);

            SubjectKeyIdentifierConfig differentConfig = new SubjectKeyIdentifierConfig();
            differentConfig.setPresent(true);
            differentConfig.setKeyIdentifier(new byte[] {2, 3, 4, 5, 6});
            config.addExtensions(differentConfig);

            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-c9f599cfc7")
    public void duplicateDifferentIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
            newConfig.setPresent(true);
            newConfig.setKeyIdentifier(new byte[] {1, 2, 3, 4, 5});
            config.addExtensions(newConfig);

            SubjectKeyIdentifierConfig differentConfig = new SubjectKeyIdentifierConfig();
            differentConfig.setPresent(true);
            differentConfig.setKeyIdentifier(new byte[] {2, 3, 4, 5, 6});
            config.addExtensions(differentConfig);

            config.setIncludeExtensions(true);
        });
    }
}
