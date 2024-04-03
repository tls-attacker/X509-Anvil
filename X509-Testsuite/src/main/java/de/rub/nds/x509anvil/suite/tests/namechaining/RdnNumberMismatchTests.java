package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
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
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import de.rub.nds.x509attacker.x509.model.Name;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import static de.rub.nds.x509anvil.framework.x509.config.X509Util.addDnQualifierToName;

public class RdnNumberMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two distinguished names DN1 and DN2 match if they have the same number of RDNs")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void missingRdn(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, missingRdnModifier());
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two distinguished names DN1 and DN2 match if they have the same number of RDNs")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void additionalRdn(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, additionalRdnModifier());
        Assertions.assertFalse(result.isValid());
    }

    // Ads an additional "distinguished name qualifier" to the intermediate's subject
    private static X509CertificateModifier missingRdnModifier() {
        return (certificate, config, previousConfig) -> {
            if (config.isIntermediate()) {
                Name subject = certificate.getTbsCertificate().getSubject();
                addDnQualifierToName(subject);
            }
        };
    }

    // Ads an additional "distinguished name qualifier" to the entity's issuer
    private static X509CertificateModifier additionalRdnModifier() {
        return (certificate, config, previousConfig) -> {
            if (config.isEntity()) {
                Name issuer = certificate.getTbsCertificate().getIssuer();
                addDnQualifierToName(issuer);
            }
        };
    }
}
