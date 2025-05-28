package de.rub.nds.x509anvil.suite.tests.basicfields.subjectpkinfo;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

public class SubjectPublicKeyInfoNotPresentTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-45174189ef")
    public void noSubjectPublicKeyInfoEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true,
        (X509CertificateConfigModifier) config ->
        config.setIncludeSubjectPublicKeyInfo(false));
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-d3f8dfc444")
    public void noSubjectPublicKeyInfoIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
        (X509CertificateConfigModifier) config ->
        config.setIncludeSubjectPublicKeyInfo(false));
    }


}
