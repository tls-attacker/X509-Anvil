package de.rub.nds.x509anvil.suite.tests.basicfields.subject;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

public class SubjectNotPresentTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-24f7012913")
    public void noSubjectEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true,
        (X509CertificateConfigModifier) config ->
        config.setIncludeSubject(false));
    }


    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-e026d7520e")
    public void noSubjectIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
        (X509CertificateConfigModifier) config ->
        config.setIncludeSubject(false));
    }

}
