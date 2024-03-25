package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
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

public class BasicConstraintsWithoutKeyCertSignTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "6.1.4. Preparation for Certificate i+1",
            text = "(n)  If a key usage extension is present, verify that the keyCertSign bit is set.")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @ValueConstraint(identifier = "entity.ext_basic_constraints_present", method = "enabled")
    @AnvilTest
    public void basicConstraintsWithoutKeyCert(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        if (chainConfig.getEntityCertificateConfig().extension(ExtensionType.KEY_USAGE).isPresent()) {
            KeyUsageExtensionConfig keyUsageExtensionConfig = (KeyUsageExtensionConfig)
                    chainConfig.getEntityCertificateConfig().extension(ExtensionType.KEY_USAGE);
            keyUsageExtensionConfig.setKeyCertSign(false);
        }
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
