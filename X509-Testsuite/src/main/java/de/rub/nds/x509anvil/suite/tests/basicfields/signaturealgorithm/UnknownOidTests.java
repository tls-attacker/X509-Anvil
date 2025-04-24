package de.rub.nds.x509anvil.suite.tests.basicfields.signaturealgorithm;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import org.junit.jupiter.api.Assertions;

import java.util.List;

public class UnknownOidTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.1.2. signatureAlgorithm and 4.1.2.3")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void unknownOidTbsEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        generatedCertificates.get(generatedCertificates.size()-1).getTbsCertificate().getSignature().getAlgorithm().setValue("1.2.3.4.5.6.7.8");
        VerifierResult result = testRunner.execute(certificateChainConfig.getEntityCertificateConfig(), generatedCertificates);
        Assertions.assertFalse(result.isValid());
    }
    //    TODO: Implement List acception in assertInvalid?

    @Specification(document = "RFC 5280", section = "4.1.1.2. signatureAlgorithm and 4.1.2.3")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void unknownOidTbsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        generatedCertificates.get(generatedCertificates.size()-2).getTbsCertificate().getSignature().getAlgorithm().setValue("1.2.3.4.5.6.7.8");
        VerifierResult result = testRunner.execute(certificateChainConfig.getEntityCertificateConfig(), generatedCertificates);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1.2.3.  Signature")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void unknownOidCertEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        generatedCertificates.get(generatedCertificates.size()-1).getSignatureAlgorithmIdentifier().getAlgorithm().setValue("1.2.3.4.5.6.7.8");
        VerifierResult result = testRunner.execute(certificateChainConfig.getEntityCertificateConfig(), generatedCertificates);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1.2.3.  Signature")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void unknownOidCertIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        generatedCertificates.get(generatedCertificates.size()-2).getSignatureAlgorithmIdentifier().getAlgorithm().setValue("1.2.3.4.5.6.7.8");
        VerifierResult result = testRunner.execute(certificateChainConfig.getEntityCertificateConfig(), generatedCertificates);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1.1.2. signatureAlgorithm and 4.1.2.3")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void unknownOidTbsAndCertEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        generatedCertificates.get(generatedCertificates.size()-1).getSignatureAlgorithmIdentifier().getAlgorithm().setValue("1.2.3.4.5.6.7.8");
        generatedCertificates.get(generatedCertificates.size()-1).getTbsCertificate().getSignature().getAlgorithm().setValue("1.2.3.4.5.6.7.8");
        VerifierResult result = testRunner.execute(certificateChainConfig.getEntityCertificateConfig(), generatedCertificates);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1.1.2. signatureAlgorithm and 4.1.2.3")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void unknownOidTbsAndCertIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        generatedCertificates.get(generatedCertificates.size()-2).getSignatureAlgorithmIdentifier().getAlgorithm().setValue("1.2.3.4.5.6.7.8");
        generatedCertificates.get(generatedCertificates.size()-2).getTbsCertificate().getSignature().getAlgorithm().setValue("1.2.3.4.5.6.7.8");
        VerifierResult result = testRunner.execute(certificateChainConfig.getEntityCertificateConfig(), generatedCertificates);
        Assertions.assertFalse(result.isValid());
    }
}
