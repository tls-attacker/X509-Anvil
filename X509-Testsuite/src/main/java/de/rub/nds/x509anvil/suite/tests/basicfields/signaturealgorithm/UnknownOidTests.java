package de.rub.nds.x509anvil.suite.tests.basicfields.signaturealgorithm;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509anvil.suite.tests.util.Modifiers;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.util.List;

public class UnknownOidTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.1.2. signatureAlgorithm and 4.1.2.3")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void unknownOidEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        Asn1ObjectIdentifier signatureAlgorithmAsn1 = (Asn1ObjectIdentifier) X509Util.getAsn1ElementByIdentifierPath(
                generatedCertificates.get(generatedCertificates.size()-1),
                "signatureAlgorithm", "algorithm");
        signatureAlgorithmAsn1.setValue("1.2.3.4.5.6.7.8");
        VerifierResult result = testRunner.execute(generatedCertificates, certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1.1.2. signatureAlgorithm and 4.1.2.3")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void unknownOidIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        Asn1ObjectIdentifier signatureAlgorithmAsn1 = (Asn1ObjectIdentifier) X509Util.getAsn1ElementByIdentifierPath(
                generatedCertificates.get(generatedCertificates.size()-2),
                "signatureAlgorithm", "algorithm");
        signatureAlgorithmAsn1.setValue("1.2.3.4.5.6.7.8");
        VerifierResult result = testRunner.execute(generatedCertificates, certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1.1.2. signatureAlgorithm and 4.1.2.3")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void unknownOidInBothFieldsEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.addModifier(Modifiers.tbsSignatureUnknownOidModifier(true));
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        Asn1ObjectIdentifier signatureAlgorithmAsn1 = (Asn1ObjectIdentifier) X509Util.getAsn1ElementByIdentifierPath(
                generatedCertificates.get(generatedCertificates.size()-1),
                "signatureAlgorithm", "algorithm");
        signatureAlgorithmAsn1.setValue("1.2.3.4.5.6.7.8");
        VerifierResult result = testRunner.execute(generatedCertificates, certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1.1.2. signatureAlgorithm and 4.1.2.3")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void unknownOidInBothFieldsIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.addModifier(Modifiers.tbsSignatureUnknownOidModifier(false));
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        Asn1ObjectIdentifier signatureAlgorithmAsn1 = (Asn1ObjectIdentifier) X509Util.getAsn1ElementByIdentifierPath(
                generatedCertificates.get(generatedCertificates.size()-2),
                "signatureAlgorithm", "algorithm");
        signatureAlgorithmAsn1.setValue("1.2.3.4.5.6.7.8");
        VerifierResult result = testRunner.execute(generatedCertificates, certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
