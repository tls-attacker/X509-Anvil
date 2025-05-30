package de.rub.nds.x509anvil.suite.tests.basicfields.signaturealgorithm;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;

public class SignatureAlgorithmMismatchTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-51110d0302")
    public void signatureAlgorithmFieldDoesntMatchAlgorithmEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setDifferentSignatureAlgorithmOid(TestUtils.getNonMatchingAlgorithmOid(config.getSignatureAlgorithm()).getSignatureAndHashAlgorithm().getOid()));
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-77e4d2a826")
    public void signatureAlgorithmFieldDoesntMatchAlgorithmIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setDifferentSignatureAlgorithmOid(TestUtils.getNonMatchingAlgorithmOid(config.getSignatureAlgorithm()).getSignatureAndHashAlgorithm().getOid()));
    }
}
