package de.rub.nds.x509anvil.suite.tests.chain;

import de.rub.nds.anvilcore.annotation.AnvilTest;
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
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.util.List;

public class DuplicateCertificateTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "6.1 Basic Path Validation",
            text = "A certificate MUST NOT appear more than once in a prospective certification path.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @AnvilTest
    public void duplicateRoot(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> certificateChain = certificateChainGenerator.retrieveCertificateChain();
        certificateChain.add(0, certificateChain.get(0));
        VerifierResult result = testRunner.execute(certificateChain);
        Assertions.assertFalse(result.isValid());
    }
    //    TODO: create a new assert method that accepts lists and check for the occurrences of LIST functions?

    @Specification(document = "RFC 5280", section = "6.1 Basic Path Validation",
            text = "A certificate MUST NOT appear more than once in a prospective certification path.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @AnvilTest
    public void duplicateIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> certificateChain = certificateChainGenerator.retrieveCertificateChain();
        certificateChain.add(1, certificateChain.get(1));
        VerifierResult result = testRunner.execute(certificateChain);
        Assertions.assertFalse(result.isValid());
    }



    @Specification(document = "RFC 5280", section = "6.1 Basic Path Validation",
            text = "A certificate MUST NOT appear more than once in a prospective certification path.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @AnvilTest
    public void duplicateEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(certificateChainConfig);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> certificateChain = certificateChainGenerator.retrieveCertificateChain();
        certificateChain.add(certificateChain.get(certificateChain.size()-1));
        VerifierResult result = testRunner.execute(certificateChain);
        Assertions.assertFalse(result.isValid());
    }
}
