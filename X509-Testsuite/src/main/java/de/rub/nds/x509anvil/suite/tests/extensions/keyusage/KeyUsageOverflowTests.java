package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.KeyUsageConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class KeyUsageOverflowTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage")
    @SeverityLevel(Severity.WARNING)
    @AnvilTest(id = "")
    public void keyUsageOverflowAppend1Entity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            KeyUsageConfig keyUsageConfig = (KeyUsageConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.KEY_USAGE);
            keyUsageConfig.setPresent(true);

            keyUsageConfig.setDigitalSignature(true);
            keyUsageConfig.setKeyAgreement(false);
            keyUsageConfig.setKeyCertSign(false);
            keyUsageConfig.setKeyEncipherment(false);

            keyUsageConfig.setNonRepudiation(true);
            keyUsageConfig.setOverflowInvalidation(true);
            keyUsageConfig.setOverflowWithOne(true);
            config.setIncludeExtensions(true);
        });
    }


    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage")
    @SeverityLevel(Severity.WARNING)
    @AnvilTest(id = "")
    public void keyUsageOverflowAppend1Intermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            KeyUsageConfig keyUsageConfig = (KeyUsageConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.KEY_USAGE);
            keyUsageConfig.setPresent(true);

            keyUsageConfig.setDigitalSignature(true);
            keyUsageConfig.setKeyAgreement(true);
            keyUsageConfig.setKeyCertSign(true);
            keyUsageConfig.setKeyEncipherment(true);

            keyUsageConfig.setNonRepudiation(true);
            keyUsageConfig.setOverflowInvalidation(true);
            keyUsageConfig.setOverflowWithOne(true);
            config.setIncludeExtensions(true);
        });
    }

    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage")
    @SeverityLevel(Severity.WARNING)
    @AnvilTest(id = "")
    public void keyUsageOverflowAppend0Entity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            KeyUsageConfig keyUsageConfig = (KeyUsageConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.KEY_USAGE);
            keyUsageConfig.setPresent(true);

            keyUsageConfig.setDigitalSignature(true);
            keyUsageConfig.setKeyAgreement(false);
            keyUsageConfig.setKeyCertSign(false);
            keyUsageConfig.setKeyEncipherment(false);

            keyUsageConfig.setNonRepudiation(true);
            keyUsageConfig.setOverflowInvalidation(true);
            keyUsageConfig.setOverflowWithOne(false);
            config.setIncludeExtensions(true);
        });
    }


    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage")
    @SeverityLevel(Severity.WARNING)
    @AnvilTest(id = "")
    public void keyUsageOverflowAppend0Intermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            KeyUsageConfig keyUsageConfig = (KeyUsageConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.KEY_USAGE);
            keyUsageConfig.setPresent(true);

            keyUsageConfig.setDigitalSignature(true);
            keyUsageConfig.setKeyAgreement(false);
            keyUsageConfig.setKeyCertSign(false);
            keyUsageConfig.setKeyEncipherment(false);

            keyUsageConfig.setNonRepudiation(true);
            keyUsageConfig.setOverflowInvalidation(true);
            keyUsageConfig.setOverflowWithOne(false);
            config.setIncludeExtensions(true);
        });
    }
}
