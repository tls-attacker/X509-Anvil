package de.rub.nds.x509anvil.suite.tests.extensions.basicconstraints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class InterCertWithCaNotSetTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-db7489730f")
    public void intermediateCertWithCaNotSet(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            BasicConstraintsConfig basicConstraintsConfig = (BasicConstraintsConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.BASIC_CONSTRAINTS);
            basicConstraintsConfig.setPresent(true);
            basicConstraintsConfig.setCritical(true);
            basicConstraintsConfig.setCa(false);
            basicConstraintsConfig.setIncludeCA(DefaultEncodingRule.FOLLOW_DEFAULT);
        });
    }
}

