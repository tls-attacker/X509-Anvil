package de.rub.nds.x509anvil.suite.tests.extensions.crldistributionpoints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.CrlDistributionPointsConfig;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.x509.model.extensions.ReasonFlags;
import org.junit.jupiter.api.TestInfo;

import java.util.*;

public class CRLDPUriSemanticsTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-crldp-s4-1")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void noUri(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {

            List<ExtensionConfig> extensionConfigList = config.getExtensions();
            for (ExtensionConfig extensionConfig : extensionConfigList) {
                if (extensionConfig.getExtensionId().toString().equals("2.5.29.31")) {
                    CrlDistributionPointsConfig crldpconfig = (CrlDistributionPointsConfig) extensionConfig;
                    crldpconfig.getDistributionPointList().get(0).getDistributionPointName().getFullName().getGeneralNames().get(0).setGeneralNameConfigValue("");
                }
            }
            config.setExtensions(extensionConfigList);
        }, testInfo);
    }


    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-crldp-s4-2")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void reasonsMismatch(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            Set<String> onlySomeReasons = new HashSet<>();
            onlySomeReasons.add("keyCompromise");
            config.getCrlConfigs().get(0).setOnlySomeReasons(onlySomeReasons);
            ReasonFlags reasonFlags = new ReasonFlags("reasonFlags");
            reasonFlags.setSuperseded(true);
            List<ExtensionConfig> extensionConfigList = config.getExtensions();
            for (ExtensionConfig extensionConfig : extensionConfigList) {
                if (extensionConfig.getExtensionId().toString().equals("2.5.29.31")) {
                    CrlDistributionPointsConfig crldpconfig = (CrlDistributionPointsConfig) extensionConfig;
                    crldpconfig.getDistributionPointList().get(0).setReasons(reasonFlags);
                }
            }
            config.setExtensions(extensionConfigList);
        }, testInfo);
    }
}
