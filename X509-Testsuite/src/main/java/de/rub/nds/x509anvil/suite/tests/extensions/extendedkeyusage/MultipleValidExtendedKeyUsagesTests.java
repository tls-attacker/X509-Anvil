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
import org.junit.jupiter.api.TestInfo;

import java.util.List;

public class MultipleValidExtendedKeyUsagesTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-999f499fe2")
    public void multipleValidExtendedKeyUsagesEntity(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> {
            ExtendedKeyUsageConfig keyUsageConfig = new ExtendedKeyUsageConfig();
            keyUsageConfig.setExtendedKeyUsages(List.of(ExtendedKeyUsageType.CLIENT_AUTH,  ExtendedKeyUsageType.SERVER_AUTH, ExtendedKeyUsageType.EMAIL_PROECTION));
            keyUsageConfig.setPresent(true);
            config.addExtensions(keyUsageConfig);
            config.setIncludeExtensions(true);
        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:extensions_present")
    @AnvilTest(id = "extension-130f887ee2")
    public void multipleValidExtendedKeyUsagesIntermediate(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, false, (X509CertificateConfigModifier) config -> {
            ExtendedKeyUsageConfig keyUsageConfig = new ExtendedKeyUsageConfig();
            keyUsageConfig.setExtendedKeyUsages(List.of(ExtendedKeyUsageType.CLIENT_AUTH,  ExtendedKeyUsageType.SERVER_AUTH, ExtendedKeyUsageType.EMAIL_PROECTION));
            keyUsageConfig.setPresent(true);
            config.addExtensions(keyUsageConfig);
            config.setIncludeExtensions(true);
        }, testInfo);
    }
}
