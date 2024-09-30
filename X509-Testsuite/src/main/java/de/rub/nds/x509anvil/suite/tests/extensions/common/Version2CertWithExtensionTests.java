package de.rub.nds.x509anvil.suite.tests.extensions.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class Version2CertWithExtensionTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.extensions_present", method = "enabled")
    @AnvilTest
    public void version1CertWithExtensionsEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
        /*
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getEntityCertificateConfig().setVersion(1);
        chainConfig.getEntityCertificateConfig().extension(ExtensionType.KEY_USAGE).setPresent(true);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
         */
    }
//    public void version1CertWithExtensionsEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//        assertInvalid(argumentsAccessor, testRunner, true, (X509CertificateConfigModifier) config -> {
//            config.setVersion(1);
//            config.extension(ExtensionType.KEY_USAGE).setPresent(true);
//        });
//    }


    @Specification(document = "RFC 5280", section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.extensions_present", method = "enabled")
    @AnvilTest
    public void version1CertWithExtensionsIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
        /*
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).setVersion(1);
        chainConfig.getIntermediateConfig(0).extension(ExtensionType.KEY_USAGE).setPresent(true);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
         */
    }
//    public void version1CertWithExtensionsIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//        assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config -> {
//            config.setVersion(1);
//            config.extension(ExtensionType.KEY_USAGE).setPresent(true);
//        });
//    }

}
