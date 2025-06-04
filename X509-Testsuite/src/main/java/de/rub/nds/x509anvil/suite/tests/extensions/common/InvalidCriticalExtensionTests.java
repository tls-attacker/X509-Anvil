package de.rub.nds.x509anvil.suite.tests.extensions.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class InvalidCriticalExtensionTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present, entity:ext_basic_constraints_present, entity:ext_basic_constraints_critical")
    @AnvilTest(id = "extension-199eb869ce")
    public void invalidCriticalSubjectKeyIdentifierEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            BasicConstraintsConfig basicConstraintsConfig = (BasicConstraintsConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.BASIC_CONSTRAINTS);
            basicConstraintsConfig.setCritical(true);
            basicConstraintsConfig.setPresent(true);
            basicConstraintsConfig.setInvalidExtensionContent(true);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:extensions_present, inter0:ext_basic_constraints_present, inter0:ext_basic_constraints_critical")
    @AnvilTest(id = "extension-5ad1c94f1c")
    public void invalidCriticalSubjectKeyIdentifierIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            BasicConstraintsConfig basicConstraintsConfig = (BasicConstraintsConfig) X509CertificateConfigUtil.getExtensionConfig(config, X509ExtensionType.BASIC_CONSTRAINTS);
            basicConstraintsConfig.setCritical(true);
            basicConstraintsConfig.setPresent(true);
            basicConstraintsConfig.setInvalidExtensionContent(true);
        });
    }
}
