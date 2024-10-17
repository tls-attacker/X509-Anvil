package de.rub.nds.x509anvil.suite.tests.basicfields.signaturealgorithm;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.util.List;

public class SignatureAlgorithmMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.1.2. signatureAlgorithm",
            text = "This field MUST contain the same algorithm identifier as the signature field in the sequence tbsCertificate (Section 4.1.2.3).")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void signatureAlgorithmFieldDoesntMatchAlgorithmEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {

        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);

        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);

        certificateChainGenerator.generateCertificateChain();

        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();

        Asn1ObjectIdentifier signatureAlgorithmAsn1 = generatedCertificates.get(generatedCertificates.size()-1).getTbsCertificate().getSignature().getAlgorithm();

        signatureAlgorithmAsn1.setValue(TestUtils.getNonMatchingAlgorithmOid(certificateChainConfig.getIssuerConfigOf(
                certificateChainConfig.getEntityCertificateConfig()).getDefaultSignatureAlgorithm()).getSignatureAndHashAlgorithm().getOid().toString());

        VerifierResult result = testRunner.execute(generatedCertificates);

        Assertions.assertFalse(result.isValid());
    }

//    TODO: Implement List acception in assertInvalid?

    @Specification(document = "RFC 5280", section = "4.1.1.2. signatureAlgorithm",
            text = "This field MUST contain the same algorithm identifier as the signature field in the sequence tbsCertificate (Section 4.1.2.3).")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void signatureAlgorithmFieldDoesntMatchAlgorithmIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        Asn1ObjectIdentifier signatureAlgorithmAsn1 = generatedCertificates.get(generatedCertificates.size()-2).getTbsCertificate().getSignature().getAlgorithm();
        signatureAlgorithmAsn1.setValue(TestUtils.getNonMatchingAlgorithmOid(certificateChainConfig.getIssuerConfigOf(
                certificateChainConfig.getLastSigningConfig()).getDefaultSignatureAlgorithm()).getSignatureAndHashAlgorithm().getOid().toString());
        VerifierResult result = testRunner.execute(generatedCertificates);
        Assertions.assertFalse(result.isValid());
    }
}
