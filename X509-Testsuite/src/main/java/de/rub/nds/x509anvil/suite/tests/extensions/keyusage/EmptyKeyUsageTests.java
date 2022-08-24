package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
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
import de.rub.nds.x509anvil.framework.x509.config.extension.KeyUsageExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.suite.tests.util.Constraints;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class EmptyKeyUsageTests extends X509AnvilTest {

        @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage",
                text = "When the keyUsage extension appears in a certificate, at least one of the bits MUST be set to 1.")
        @SeverityLevel(Severity.WARNING)
        @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
        @TestStrength(2)
        @ValueConstraint(identifier = "entity.ext_key_usage_present", clazz = Constraints.class, method = "enabled")
        @AnvilTest
        public void emptyKeyUsageEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
                X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
                KeyUsageExtensionConfig keyUsageExtensionConfig = (KeyUsageExtensionConfig)
                        chainConfig.getEntityCertificateConfig().extension(ExtensionType.KEY_USAGE);
                keyUsageExtensionConfig.unsetAllBits();
                VerifierResult result = testRunner.execute(chainConfig);
                Assertions.assertFalse(result.isValid());
        }
}
