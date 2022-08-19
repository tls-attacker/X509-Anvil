package de.rub.nds.x509anvil.suite.tests.basicfields;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.RFC;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class TbsSignatureTests extends X509AnvilTest {

    @RFC(number = 5280, section = "4.1.2.3.  Signature",
            text = "This field MUST contain the same algorithm identifier as the signatureAlgorithm field in the sequence Certificate (Section 4.1.1.2).")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void tbsSignatureDoesntMatchAlgorithmEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(certificateChainConfig, createTbsSignatureDoesntMatchSignatureAlgorithmModifier(true));
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.1.2.3.  Signature",
            text = "This field MUST contain the same algorithm identifier as the signatureAlgorithm field in the sequence Certificate (Section 4.1.1.2).")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void tbsSignatureDoesntMatchAlgorithmIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(certificateChainConfig, createTbsSignatureDoesntMatchSignatureAlgorithmModifier(false));
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.1.2.3.  Signature")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest(description = "Checks if the application rejects certificates where the signature algorithm in tbsCertificate.signature is unknown")
    public void unknownOidEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(certificateChainConfig, createUnknownOidModifier(true));
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.1.2.3.  Signature")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest(description = "Checks if the application rejects certificates where the signature algorithm in tbsCertificate.signature is unknown")
    public void unknownOidIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(certificateChainConfig, createUnknownOidModifier(false));
        Assertions.assertFalse(result.isValid());
    }

    public static X509CertificateModifier createTbsSignatureDoesntMatchSignatureAlgorithmModifier(boolean entity) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1ObjectIdentifier tbsSignatureAsn1 = (Asn1ObjectIdentifier) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "signature", "algorithm");
                tbsSignatureAsn1.setValue(TestUtils.getNonMatchingAlgorithmOid(previousConfig.getSignatureAlgorithm()));
            }
        };
    }

    public static X509CertificateModifier createUnknownOidModifier(boolean entity) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1ObjectIdentifier tbsSignatureAsn1 = (Asn1ObjectIdentifier) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "signature", "algorithm");
                tbsSignatureAsn1.setValue("1.2.3.4.5.6.7.8");
            }
        };
    }
}
