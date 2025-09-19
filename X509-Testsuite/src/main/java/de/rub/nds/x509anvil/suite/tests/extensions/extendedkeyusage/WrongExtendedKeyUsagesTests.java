package de.rub.nds.x509anvil.suite.tests.extensions.extendedkeyusage;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.ExtendedKeyUsageConfig;
import de.rub.nds.x509attacker.constants.ExtendedKeyUsageType;

import java.util.List;

public class WrongExtendedKeyUsagesTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-930f499fe2")
    public void wrongExtendedKeyUsagesEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            ExtendedKeyUsageConfig keyUsageConfig = new ExtendedKeyUsageConfig();
            keyUsageConfig.setExtendedKeyUsages(List.of(ExtendedKeyUsageType.EMAIL_PROECTION));
            keyUsageConfig.setPresent(true);
            config.addExtensions(keyUsageConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:extensions_present")
    @AnvilTest(id = "extension-930f987fe2")
    public void wrongExtendedKeyUsagesIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            ExtendedKeyUsageConfig keyUsageConfig = new ExtendedKeyUsageConfig();
            keyUsageConfig.setExtendedKeyUsages(List.of(ExtendedKeyUsageType.EMAIL_PROECTION));
            keyUsageConfig.setPresent(true);
            config.addExtensions(keyUsageConfig);
            config.setIncludeExtensions(true);
        });
    }
}
