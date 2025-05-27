package de.rub.nds.x509anvil.suite.tests.basicfields;

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

public class AppendUnexpectedCertificateFieldTest extends X509AnvilTest {

    @Specification(document = "RFC 5280", text = "Adds an unexpected field to the certificate. This does not conform with the specification and needs to fail.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-e0bcce347c")
    public void appendUnexpectedFieldEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setAppendUnexpectedCertificateField(true));
    }

    @Specification(document = "RFC 5280", text = "Adds an unexpected field to the certificate. This does not conform with the specification and needs to fail.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-6d1ba61fab")
    public void appendUnexpectedFieldIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setAppendUnexpectedCertificateField(true));
    }
}
