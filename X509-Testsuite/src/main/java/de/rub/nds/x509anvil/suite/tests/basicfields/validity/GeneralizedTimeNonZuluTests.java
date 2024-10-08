package de.rub.nds.x509anvil.suite.tests.basicfields.validity;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
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
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class GeneralizedTimeNonZuluTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.2.5.2. GeneralizedTime",
            text = "For the purposes of this profile, GeneralizedTime values MUST be expressed in Greenwich Mean Time (Zulu)")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "entity.not_before")
    @AnvilTest
    public void notBeforeEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getEntityCertificateConfig().setNotBefore(new DateTime(2020, 1, 1, 0, 0, 0, DateTimeZone.forOffsetHours(1)));
        chainConfig.getEntityCertificateConfig().setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1.2.5.2. GeneralizedTime",
            text = "For the purposes of this profile, GeneralizedTime values MUST be expressed in Greenwich Mean Time (Zulu)")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "inter0.not_before")
    @AnvilTest
    public void notBeforeIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).setNotBefore(new DateTime(2020, 1, 1, 0, 0, 0, DateTimeZone.forOffsetHours(1)));
        chainConfig.getIntermediateConfig(0).setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1.2.5.2. GeneralizedTime",
            text = "For the purposes of this profile, GeneralizedTime values MUST be expressed in Greenwich Mean Time (Zulu)")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "entity.not_after")
    @AnvilTest
    public void notAfterEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getEntityCertificateConfig().setNotBefore(new DateTime(2050, 1, 1, 0, 0, 0, DateTimeZone.forOffsetHours(1)));
        chainConfig.getEntityCertificateConfig().setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1.2.5.2. GeneralizedTime",
            text = "For the purposes of this profile, GeneralizedTime values MUST be expressed in Greenwich Mean Time (Zulu)")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "inter0.not_after")
    @AnvilTest
    public void notAfterIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).setNotBefore(new DateTime(2050, 1, 1, 0, 0, 0, DateTimeZone.forOffsetHours(1)));
        chainConfig.getIntermediateConfig(0).setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
