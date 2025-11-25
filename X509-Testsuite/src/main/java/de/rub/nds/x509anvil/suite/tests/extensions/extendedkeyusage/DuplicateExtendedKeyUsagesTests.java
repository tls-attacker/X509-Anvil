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

public class DuplicateExtendedKeyUsagesTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-999f480fe2")
    public void duplicateIdenticalExtendedKeyUsagesEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            ExtendedKeyUsageConfig keyUsageConfig = new ExtendedKeyUsageConfig();
            keyUsageConfig.setExtendedKeyUsages(List.of(ExtendedKeyUsageType.CLIENT_AUTH,  ExtendedKeyUsageType.SERVER_AUTH));
            keyUsageConfig.setPresent(true);
            config.addExtensions(keyUsageConfig);
            config.addExtensions(keyUsageConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-999f481fe2")
    public void duplicateIdenticalExtendedKeyUsagesIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            ExtendedKeyUsageConfig keyUsageConfig = new ExtendedKeyUsageConfig();
            keyUsageConfig.setExtendedKeyUsages(List.of(ExtendedKeyUsageType.CLIENT_AUTH,  ExtendedKeyUsageType.SERVER_AUTH));
            keyUsageConfig.setPresent(true);
            config.addExtensions(keyUsageConfig);
            config.addExtensions(keyUsageConfig);
        });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-999f482fe2")
    public void duplicateDifferentExtendedKeyUsagesEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            ExtendedKeyUsageConfig keyUsageConfig = new ExtendedKeyUsageConfig();
            keyUsageConfig.setExtendedKeyUsages(List.of(ExtendedKeyUsageType.CLIENT_AUTH,  ExtendedKeyUsageType.SERVER_AUTH));
            keyUsageConfig.setPresent(true);
            config.addExtensions(keyUsageConfig);

            ExtendedKeyUsageConfig keyUsageConfigDifferent = new ExtendedKeyUsageConfig();
            keyUsageConfigDifferent.setExtendedKeyUsages(List.of(ExtendedKeyUsageType.CLIENT_AUTH,  ExtendedKeyUsageType.SERVER_AUTH, ExtendedKeyUsageType.EMAIL_PROECTION));
            keyUsageConfigDifferent.setPresent(true);
            config.addExtensions(keyUsageConfigDifferent);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-999f483fe2")
    public void duplicateDifferentExtendedKeyUsagesIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            ExtendedKeyUsageConfig keyUsageConfig = new ExtendedKeyUsageConfig();
            keyUsageConfig.setExtendedKeyUsages(List.of(ExtendedKeyUsageType.CLIENT_AUTH,  ExtendedKeyUsageType.SERVER_AUTH));
            keyUsageConfig.setPresent(true);
            config.addExtensions(keyUsageConfig);

            ExtendedKeyUsageConfig keyUsageConfigDifferent = new ExtendedKeyUsageConfig();
            keyUsageConfigDifferent.setExtendedKeyUsages(List.of(ExtendedKeyUsageType.CLIENT_AUTH,  ExtendedKeyUsageType.SERVER_AUTH, ExtendedKeyUsageType.EMAIL_PROECTION));
            keyUsageConfigDifferent.setPresent(true);
            config.addExtensions(keyUsageConfigDifferent);
        });
    }
}
