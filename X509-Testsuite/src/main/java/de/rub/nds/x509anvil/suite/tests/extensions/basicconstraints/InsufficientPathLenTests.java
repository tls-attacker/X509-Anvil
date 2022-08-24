package de.rub.nds.x509anvil.suite.tests.extensions.basicconstraints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.extension.BasicConstraintsExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class InsufficientPathLenTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.9. Basic Constraints",
            text = "In this case, it [the pathLenConstraint field] gives the maximum number of non-self-issued intermediate certificates that may " +
                    "follow this certificate in a valid certification path.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void insufficientPathLenChainLength4(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        BasicConstraintsExtensionConfig basicConstraintsExtensionConfig = (BasicConstraintsExtensionConfig)
                chainConfig.getIntermediateConfig(0).extension(ExtensionType.BASIC_CONSTRAINTS);
        basicConstraintsExtensionConfig.setPresent(true);
        basicConstraintsExtensionConfig.setCa(true);
        basicConstraintsExtensionConfig.setPathLenConstraintPresent(true);
        basicConstraintsExtensionConfig.setPathLenConstraint(0);
        chainConfig.getIntermediateConfig(0).extension(ExtensionType.BASIC_CONSTRAINTS).setPresent(true);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.2.1.9. Basic Constraints",
            text = "In this case, it [the pathLenConstraint field] gives the maximum number of non-self-issued intermediate certificates that may " +
                    "follow this certificate in a valid certification path.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 5, maxLength = 5, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void insufficientPathLenChainLength5(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        BasicConstraintsExtensionConfig basicConstraintsExtensionConfig = (BasicConstraintsExtensionConfig)
                chainConfig.getIntermediateConfig(0).extension(ExtensionType.BASIC_CONSTRAINTS);
        basicConstraintsExtensionConfig.setPresent(true);
        basicConstraintsExtensionConfig.setCa(true);
        basicConstraintsExtensionConfig.setPathLenConstraintPresent(true);
        basicConstraintsExtensionConfig.setPathLenConstraint(1);
        chainConfig.getIntermediateConfig(0).extension(ExtensionType.BASIC_CONSTRAINTS).setPresent(true);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.2.1.9. Basic Constraints",
            text = "In this case, it [the pathLenConstraint field] gives the maximum number of non-self-issued intermediate certificates that may " +
                    "follow this certificate in a valid certification path.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 10, maxLength = 10, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void insufficientPathLenChainLength10(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        BasicConstraintsExtensionConfig basicConstraintsExtensionConfig = (BasicConstraintsExtensionConfig)
                chainConfig.getIntermediateConfig(0).extension(ExtensionType.BASIC_CONSTRAINTS);
        basicConstraintsExtensionConfig.setPresent(true);
        basicConstraintsExtensionConfig.setCa(true);
        basicConstraintsExtensionConfig.setPathLenConstraintPresent(true);
        basicConstraintsExtensionConfig.setPathLenConstraint(6);
        chainConfig.getIntermediateConfig(0).extension(ExtensionType.BASIC_CONSTRAINTS).setPresent(true);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
