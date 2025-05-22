package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.KeyUsageConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class EmptyKeyUsageTests extends X509AnvilTest {

        @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage",
                text = "When the keyUsage extension appears in a certificate, at least one of the bits MUST be set to 1.")
        @SeverityLevel(Severity.WARNING)
                @AnvilTest()
        public void emptyKeyUsageEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
                assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
                        KeyUsageConfig keyUsageConfig = (KeyUsageConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.KEY_USAGE);
                        keyUsageConfig.setDigitalSignature(false);
                        keyUsageConfig.setKeyCertSign(false);
                        keyUsageConfig.setcRLSign(false);
                });
        }
}

