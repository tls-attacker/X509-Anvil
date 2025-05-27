package de.rub.nds.x509anvil.suite.tests.basicfields.subject;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

public class SubjectNotPresentTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.  Basic Certificate Fields", text = "The subject field is non-optional and must be present.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-24f7012913")
    public void noSubjectEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true,
        (X509CertificateConfigModifier) config ->
        config.setIncludeSubject(false));
    }


    @Specification(document = "RFC 5280", section = "4.1.  Basic Certificate Fields", text = "The subject field is non-optional and must be present.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-e026d7520e")
    public void noSubjectIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
        (X509CertificateConfigModifier) config ->
        config.setIncludeSubject(false));
    }

}
