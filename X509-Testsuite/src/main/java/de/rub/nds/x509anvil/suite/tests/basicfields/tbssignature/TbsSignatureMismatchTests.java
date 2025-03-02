package de.rub.nds.x509anvil.suite.tests.basicfields.tbssignature;

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
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class TbsSignatureMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.2.3.  Signature",
            text = "This field MUST contain the same algorithm identifier as the signatureAlgorithm field in the sequence Certificate (Section 4.1.1.2).")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void tbsSignatureDoesntMatchAlgorithmEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        certificateChainConfig.getEntityCertificateConfig().amendSignatureAlgorithm(
                TestUtils.getNonMatchingAlgorithmOid(
                        certificateChainConfig.getIssuerConfigOf(
                                certificateChainConfig.getEntityCertificateConfig()).getDefaultSignatureAlgorithm()).getSignatureAlgorithm());
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1.2.3.  Signature",
            text = "This field MUST contain the same algorithm identifier as the signatureAlgorithm field in the sequence Certificate (Section 4.1.1.2).")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void tbsSignatureDoesntMatchAlgorithmIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(testRunner);
        certificateChainConfig.getLastSigningConfig().amendSignatureAlgorithm(
                TestUtils.getNonMatchingAlgorithmOid(
                        certificateChainConfig.getIssuerConfigOf(
                                certificateChainConfig.getLastSigningConfig()).getDefaultSignatureAlgorithm()).getSignatureAlgorithm());
        VerifierResult result = testRunner.execute(certificateChainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
