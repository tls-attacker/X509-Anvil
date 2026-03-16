package de.rub.nds.x509anvil.suite.tests.extensions.subjectkeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.SubjectKeyIdentifierConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import org.junit.jupiter.api.TestInfo;

public class SubjectKeyIdNotPresentTests extends X509AnvilTest {
    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-128a9aac93")
    public void subjectKeyIdNotPresentIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier) config -> {
                    SubjectKeyIdentifierConfig subjectKeyIdentifierConfig =
                            (SubjectKeyIdentifierConfig)
                                    X509CertificateConfigUtil.getExtensionConfig(
                                            config, X509ExtensionType.SUBJECT_KEY_IDENTIFIER);
                    subjectKeyIdentifierConfig.setPresent(false);
                }, testInfo);
    }
}
