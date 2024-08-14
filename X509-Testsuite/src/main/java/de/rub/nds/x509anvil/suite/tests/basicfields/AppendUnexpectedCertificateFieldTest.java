package de.rub.nds.x509anvil.suite.tests.basicfields;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.asn1.model.Asn1OctetString;
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
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.util.List;

public class AppendUnexpectedCertificateFieldTest extends X509AnvilTest {

    @Specification(document = "RFC 5280")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void appendUnexpectedFieldEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();

        Asn1OctetString octetString = new Asn1OctetString("unexpectedField");
        octetString.setValue(TestUtils.createByteArray(8));
        generatedCertificates.get(generatedCertificates.size() - 1).getTbsCertificate().setEncodedChildren(ArrayUtils.addAll(generatedCertificates.get(1).getTbsCertificate().getEncodedChildren().getValue(), octetString.getContent().getValue()));

        VerifierResult result = testRunner.execute(generatedCertificates);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void appendUnexpectedFieldIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();

        Asn1OctetString octetString = new Asn1OctetString("unexpectedField");
        octetString.setValue(TestUtils.createByteArray(8));
        generatedCertificates.get(1).getTbsCertificate().setEncodedChildren(ArrayUtils.addAll(generatedCertificates.get(1).getTbsCertificate().getEncodedChildren().getValue(), octetString.getContent().getValue()));

        VerifierResult result = testRunner.execute(generatedCertificates);
        Assertions.assertFalse(result.isValid());
    }
}
