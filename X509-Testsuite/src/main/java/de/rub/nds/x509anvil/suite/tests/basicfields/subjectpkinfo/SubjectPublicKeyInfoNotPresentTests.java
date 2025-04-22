package de.rub.nds.x509anvil.suite.tests.basicfields.subjectpkinfo;

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

public class SubjectPublicKeyInfoNotPresentTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.  Basic Certificate Fields")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void noSubjectPublicKeyInfoEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true,
        (X509CertificateConfigModifier) config ->
        config.setIncludeSubjectPublicKeyInfo(false));
    }

    @Specification(document = "RFC 5280", section = "4.1.  Basic Certificate Fields")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void noSubjectPublicKeyInfoIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
        (X509CertificateConfigModifier) config ->
        config.setIncludeSubjectPublicKeyInfo(false));
    }


}
