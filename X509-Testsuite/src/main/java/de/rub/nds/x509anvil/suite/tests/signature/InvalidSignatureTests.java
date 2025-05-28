package de.rub.nds.x509anvil.suite.tests.signature;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

public class InvalidSignatureTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "signature-beb05c376e")
    public void invalidSignatureEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setSignatureInvalid(true));
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "signature-b61f8b0eae")
    public void invalidSignatureIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setSignatureInvalid(true));
    }
}
