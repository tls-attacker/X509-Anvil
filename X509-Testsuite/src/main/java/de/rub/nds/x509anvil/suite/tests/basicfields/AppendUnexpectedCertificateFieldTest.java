package de.rub.nds.x509anvil.suite.tests.basicfields;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

public class AppendUnexpectedCertificateFieldTest extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-e0bcce347c")
    public void appendUnexpectedFieldEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setAppendUnexpectedCertificateField(true));
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-6d1ba61fab")
    public void appendUnexpectedFieldIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setAppendUnexpectedCertificateField(true));
    }
}
