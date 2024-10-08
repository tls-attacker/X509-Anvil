package de.rub.nds.x509anvil.suite.tests.extensions.basicconstraints;

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
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
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
        BasicConstraintsConfig config = (BasicConstraintsConfig) X509CertificateConfigUtil.getExtensionConfig(chainConfig.getIntermediateConfig(0), X509ExtensionType.BASIC_CONSTRAINTS);
        config.setPresent(true);
        config.setCa(true);
        config.setPathLenConstraint(0);
        config.setIncludeCA(DefaultEncodingRule.ENCODE);
        config.setIncludePathLenConstraint(DefaultEncodingRule.ENCODE);
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
        BasicConstraintsConfig config = (BasicConstraintsConfig) X509CertificateConfigUtil.getExtensionConfig(chainConfig.getIntermediateConfig(0), X509ExtensionType.BASIC_CONSTRAINTS);
        config.setPresent(true);
        config.setCa(true);
        config.setPathLenConstraint(1);
        config.setIncludeCA(DefaultEncodingRule.ENCODE);
        config.setIncludePathLenConstraint(DefaultEncodingRule.ENCODE);
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
        BasicConstraintsConfig config = (BasicConstraintsConfig) X509CertificateConfigUtil.getExtensionConfig(chainConfig.getIntermediateConfig(0), X509ExtensionType.BASIC_CONSTRAINTS);
        config.setPresent(true);
        config.setCa(true);
        config.setPathLenConstraint(6);
        config.setIncludeCA(DefaultEncodingRule.ENCODE);
        config.setIncludePathLenConstraint(DefaultEncodingRule.ENCODE);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
