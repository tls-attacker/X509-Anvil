package de.rub.nds.x509anvil.suite.tests.extensions.basicconstraints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
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
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class PathlenWithoutCaSetTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.9. Basic Constraints",
            text = "CAs MUST NOT include the pathLenConstraint field unless the cA boolean is asserted")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-ef15984307")
    public void pathlenWithoutCaSetEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            BasicConstraintsConfig basicConstraintsConfig = (BasicConstraintsConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.BASIC_CONSTRAINTS);
            basicConstraintsConfig.setPresent(true);
            basicConstraintsConfig.setCa(false);
            basicConstraintsConfig.setPathLenConstraint(5);
            basicConstraintsConfig.setIncludeCA(DefaultEncodingRule.FOLLOW_DEFAULT);
            basicConstraintsConfig.setIncludePathLenConstraint(DefaultEncodingRule.ENCODE);
        });

    }
}
