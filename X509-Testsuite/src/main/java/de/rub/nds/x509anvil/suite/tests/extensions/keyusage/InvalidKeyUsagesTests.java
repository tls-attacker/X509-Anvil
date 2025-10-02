package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.KeyUsageConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;

public class InvalidKeyUsagesTests extends X509AnvilTest {
    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-9e051adef5")
    @IpmLimitations(identifiers = "inter0:ext_key_usage_additional")
    public void intermediateCertWithCertSignNotSet(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            KeyUsageConfig keyUsageConfig =
                                    (KeyUsageConfig)
                                            X509CertificateConfigUtil.getExtensionConfig(
                                                    config, X509ExtensionType.KEY_USAGE);
                            keyUsageConfig.setKeyCertSign(false);
                        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-1e2a19cef5")
    @IpmLimitations(identifiers = "entity:ext_key_usage_additional")
    public void entityInvalidUse(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            KeyUsageConfig keyUsageConfig =
                                    (KeyUsageConfig)
                                            X509CertificateConfigUtil.getExtensionConfig(
                                                    config, X509ExtensionType.KEY_USAGE);
                            keyUsageConfig.setDigitalSignature(false);
                            keyUsageConfig.setcRLSign(true);
                            keyUsageConfig.setKeyEncipherment(false);
                            keyUsageConfig.setKeyAgreement(false);
                            keyUsageConfig.setKeyCertSign(false);
                            keyUsageConfig.setDataEncipherment(false);
                            keyUsageConfig.setDecipherOnly(false);
                            keyUsageConfig.setEncipherOnly(false);
                            keyUsageConfig.setNonRepudiation(false);
                        });
    }
}
