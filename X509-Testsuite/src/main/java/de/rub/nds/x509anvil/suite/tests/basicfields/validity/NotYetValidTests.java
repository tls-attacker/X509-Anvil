package de.rub.nds.x509anvil.suite.tests.basicfields.validity;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.RFC;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.model.TimeType;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class NotYetValidTests extends X509AnvilTest {

    @RFC(number = 5280, section = "6.1.3. Basic Certificate Processing", text = "The certificate validity period includes the current time.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "entity.not_before")
    @AnvilTest
    public void notYetValidUtcEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getEntityCertificateConfig().setNotBeforeValue("400101000000Z");
        chainConfig.getEntityCertificateConfig().setNotBeforeTimeType(TimeType.UTC_TIME);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "6.1.3. Basic Certificate Processing", text = "The certificate validity period includes the current time.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "entity.not_before")
    @AnvilTest
    public void notYetValidGeneralizedEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getEntityCertificateConfig().setNotBeforeValue("20400101000000Z");
        chainConfig.getEntityCertificateConfig().setNotBeforeTimeType(TimeType.GENERALIZED_TIME);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "6.1.3. Basic Certificate Processing", text = "The certificate validity period includes the current time.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "inter0.not_before")
    @AnvilTest
    public void notYetValidUtcIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).setNotBeforeValue("400101000000Z");
        chainConfig.getIntermediateConfig(0).setNotBeforeTimeType(TimeType.UTC_TIME);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "6.1.3. Basic Certificate Processing", text = "The certificate validity period includes the current time.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "inter0.not_before")
    @AnvilTest
    public void notYetValidGeneralizedIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).setNotBeforeValue("20400101000000Z");
        chainConfig.getIntermediateConfig(0).setNotBeforeTimeType(TimeType.GENERALIZED_TIME);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
