
package de.rub.nds.x509anvil.suite.tests.extensions;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.RFC;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.KeyUsageExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class ExtensionCommonTests extends X509AnvilTest {

    @RFC(number = 5280, section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = {"entity.version", "entity.extensions_present"})
    @AnvilTest
    public void version1CertWithExtensions(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getEntityCertificateConfig().setVersion(0);
        chainConfig.getEntityCertificateConfig().setExtensionsPresent(true);
        KeyUsageExtensionConfig keyUsageExtensionConfig = (KeyUsageExtensionConfig)
                chainConfig.getEntityCertificateConfig().extension(ExtensionType.KEY_USAGE);
        keyUsageExtensionConfig.setPresent(true);
        keyUsageExtensionConfig.setCritical(true);
        keyUsageExtensionConfig.setDigitalSignature(true);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = {"entity.version", "entity.extensions_present"})
    @AnvilTest
    public void version2CertWithExtensions(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getEntityCertificateConfig().setVersion(1);
        chainConfig.getEntityCertificateConfig().setExtensionsPresent(true);
        KeyUsageExtensionConfig keyUsageExtensionConfig = (KeyUsageExtensionConfig)
                chainConfig.getEntityCertificateConfig().extension(ExtensionType.KEY_USAGE);
        keyUsageExtensionConfig.setPresent(true);
        keyUsageExtensionConfig.setCritical(true);
        keyUsageExtensionConfig.setDigitalSignature(true);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.2 Certificate Extensions",
            text = "A certificate-using system MUST reject the certificate if it encounters a critical extension it does not recognize")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = {"entity.version", "entity.extensions_present", "entity.ext_unknown_noncritical_extension_present"})
    @AnvilTest
    public void unknownCriticalExtensionEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getEntityCertificateConfig().setVersion(2);
        chainConfig.getEntityCertificateConfig().setExtensionsPresent(true);
        chainConfig.getEntityCertificateConfig().extension(ExtensionType.UNKNOWN_EXTENSION).setPresent(true);
        chainConfig.getEntityCertificateConfig().extension(ExtensionType.UNKNOWN_EXTENSION).setCritical(true);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.2 Certificate Extensions",
            text = "A certificate-using system MUST reject the certificate if it encounters a critical extension it does not recognize")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = {"inter0.version", "inter0.extensions_present", "inter0.ext_unknown_noncritical_extension_present"})
    @AnvilTest
    public void unknownCriticalExtensionIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).setVersion(2);
        chainConfig.getIntermediateConfig(0).setExtensionsPresent(true);
        chainConfig.getIntermediateConfig(0).extension(ExtensionType.UNKNOWN_EXTENSION).setPresent(true);
        chainConfig.getIntermediateConfig(0).extension(ExtensionType.UNKNOWN_EXTENSION).setCritical(true);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
