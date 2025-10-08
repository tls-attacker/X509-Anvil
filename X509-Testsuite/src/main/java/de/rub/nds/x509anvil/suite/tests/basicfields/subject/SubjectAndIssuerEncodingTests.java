package de.rub.nds.x509anvil.suite.tests.basicfields.subject;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;

public class SubjectAndIssuerEncodingTests extends X509AnvilTest{
    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-f214c1171a")
    public void bmpEncodingEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setDefaultDirectoryStringType(DirectoryStringChoiceType.BMP_STRING));
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-f149a9f71a")
    public void bmpEncodingIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setDefaultDirectoryStringType(DirectoryStringChoiceType.BMP_STRING));
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-e991a3581a")
    public void teletexEncodingEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setDefaultDirectoryStringType(DirectoryStringChoiceType.TELETEX_STRING));
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-e191a2791c")
    public void teletexEncodingIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setDefaultDirectoryStringType(DirectoryStringChoiceType.TELETEX_STRING));
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-e195f2581a")
    public void universalEncodingEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setDefaultDirectoryStringType(DirectoryStringChoiceType.UNIVERSAL_STRING));
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-e921fed89a")
    public void universalEncodingIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setDefaultDirectoryStringType(DirectoryStringChoiceType.UNIVERSAL_STRING));
    }
}
