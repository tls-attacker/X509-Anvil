package de.rub.nds.x509anvil.suite.tests.extensions.subjectkeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.SubjectKeyIdentifierConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class CriticalSubjectKeyIdTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-1ea3c5dc17")
    public void criticalSubjectKeyIdEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            SubjectKeyIdentifierConfig newConfig = new SubjectKeyIdentifierConfig();
                            newConfig.setPresent(true);
                            newConfig.setKeyIdentifier(new byte[] {1, 2, 3, 4, 5});
                            newConfig.setCritical(true);
                            config.addExtensions(newConfig);
                            config.setIncludeExtensions(true);
                        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-2d1d5dc178")
    public void criticalSubjectKeyIdIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            SubjectKeyIdentifierConfig subjectKeyIdentifierConfig =
                                    (SubjectKeyIdentifierConfig)
                                            X509CertificateConfigUtil.getExtensionConfig(
                                                    config, X509ExtensionType.SUBJECT_KEY_IDENTIFIER);
                            subjectKeyIdentifierConfig.setCritical(true);
                        });
    }
}
