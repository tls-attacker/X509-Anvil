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
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class InterCertWithoutBasicConstraintsTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.9. Basic Constraints",
            text = "Conforming CAs MUST include this extension in all CA certificates that contain public keys used to validate digital signatures on certificates")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void intermediateCertWithoutBasicConstraintsTests(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            BasicConstraintsConfig basicConstraintsConfig = (BasicConstraintsConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.BASIC_CONSTRAINTS);
            basicConstraintsConfig.setPresent(false);
        });
    }
}

