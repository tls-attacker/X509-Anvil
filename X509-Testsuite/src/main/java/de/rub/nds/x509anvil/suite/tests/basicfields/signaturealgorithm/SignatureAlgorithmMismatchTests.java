package de.rub.nds.x509anvil.suite.tests.basicfields.signaturealgorithm;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;

public class SignatureAlgorithmMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.1.2. signatureAlgorithm",
            text = "This field MUST contain the same algorithm identifier as the signature field in the sequence tbsCertificate (Section 4.1.2.3).")
    @SeverityLevel(Severity.ERROR)
    @AnvilTest(id = "basic-47ba5ecc23")
    public void signatureAlgorithmFieldDoesntMatchAlgorithmEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setDifferentSignatureAlgorithmOid(TestUtils.getNonMatchingAlgorithmOid(config.getSignatureAlgorithm()).getSignatureAndHashAlgorithm().getOid()));
    }

    @Specification(document = "RFC 5280", section = "4.1.1.2. signatureAlgorithm",
            text = "This field MUST contain the same algorithm identifier as the signature field in the sequence tbsCertificate (Section 4.1.2.3).")
    @SeverityLevel(Severity.ERROR)
    @AnvilTest(id = "basic-47ba5ecc23")
    public void signatureAlgorithmFieldDoesntMatchAlgorithmIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setDifferentSignatureAlgorithmOid(TestUtils.getNonMatchingAlgorithmOid(config.getSignatureAlgorithm()).getSignatureAndHashAlgorithm().getOid()));
    }
}
