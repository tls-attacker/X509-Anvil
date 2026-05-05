package de.rub.nds.x509anvil.suite.tests.extensions.crldistributionpoints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.crls.CrlUtils;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.CrlConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.config.extension.CrlDistributionPointsConfig;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.constants.DistributionPointNameChoiceType;
import de.rub.nds.x509attacker.constants.GeneralNameChoiceType;
import de.rub.nds.x509attacker.x509.model.GeneralName;
import de.rub.nds.x509attacker.x509.model.extensions.DistributionPoint;
import de.rub.nds.x509attacker.x509.model.extensions.DistributionPointName;
import de.rub.nds.x509attacker.x509.model.extensions.GeneralNames;
import de.rub.nds.x509attacker.x509.model.extensions.ReasonFlags;
import de.rwth.swc.coffee4j.engine.conflict.DiagnosisSet;
import org.junit.jupiter.api.TestInfo;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CRLDPNotAllReasonsTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = {"entity:extensions_present"})
    @AnvilTest(id = "extension-0123456714")
    public void invalidCase(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            /*
            If the DistributionPoint omits the reasons field, the CRL MUST include revocation information for all reasons.
             */

            // Docs: https://docs.openssl.org/master/man5/x509v3_config/#issuing-distribution-point
            Set<String> onlySomeReasons = new HashSet<>();
            onlySomeReasons.add("keyCompromise");
            config.getCrlConfigs().get(0).setOnlySomeReasons(onlySomeReasons);

        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = {"entity:extensions_present"})
    @AnvilTest(id = "extension-0123456715")
    public void validCase(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> {
            // Docs: https://docs.openssl.org/master/man5/x509v3_config/#issuing-distribution-point
            Set<String> onlySomeReasons = new HashSet<>();
            onlySomeReasons.add("keyCompromise");
            config.getCrlConfigs().get(0).setOnlySomeReasons(onlySomeReasons);
            List<ExtensionConfig> extensionConfigList = config.getExtensions();
            for (ExtensionConfig extensionConfig : extensionConfigList) {
                if (extensionConfig.getExtensionId().toString().equals("2.5.29.31")) {
                    CrlDistributionPointsConfig crldpconfig = (CrlDistributionPointsConfig) extensionConfig;
                    ReasonFlags reasonFlags = new ReasonFlags("reasonFlags");
                    reasonFlags.setKeyCompromise(true);
                    crldpconfig.getDistributionPointList().get(0).setReasons(reasonFlags);
                    CrlConfig crlConfig = new CrlConfig();
                    crlConfig.setCrlNameSuffix("_2");
                    config.getCrlConfigs().add(crlConfig);
                    DistributionPoint newDp = new DistributionPoint("new dp");
                    DistributionPointName distributionPointName = new DistributionPointName("dpn");
                    distributionPointName.setDistributionPointNameChoiceType(DistributionPointNameChoiceType.FULL_NAME);
                    GeneralNames generalNames = new GeneralNames("gns");
                    List<GeneralName> generalNameList = new ArrayList<>();
                    GeneralName generalName = new GeneralName("gn");
                    generalName.setGeneralNameChoiceTypeConfig(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER);

                    generalName.setGeneralNameConfigValue("http://172.17.0.1:8099/crls/"+config.getCrlUniqueID()+crlConfig.getCrlNameSuffix()+".crl");
                    generalNameList.add(generalName);
                    generalNames.setGeneralNames(generalNameList);
                    distributionPointName.setFullName(generalNames);
                    newDp.setDistributionPointName(distributionPointName);
                    ReasonFlags newReasonFlags = new ReasonFlags("reasonFlags2");
                    newReasonFlags.setcACompromise(true);
                    newReasonFlags.setaACompromise(true);
                    newReasonFlags.setSuperseded(true);
                    newReasonFlags.setCessationOfOperation(true);
                    newReasonFlags.setPrivilegeWithdrawn(true);
                    newReasonFlags.setAffiliationChanged(true);
                    newReasonFlags.setCertificateHold(true);
                    newReasonFlags.setKeyCompromise(true);
                    newDp.setReasons(newReasonFlags);
                    newDp.setCrlIssuer(null);
                    crldpconfig.distributionPointList.add(0,newDp);
                }
            }

        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = {"entity:extensions_present"})
    @AnvilTest(id = "extension-0123456716")
    public void reasonsMismatch(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            // Docs: https://docs.openssl.org/master/man5/x509v3_config/#issuing-distribution-point
            Set<String> onlySomeReasons = new HashSet<>();
            onlySomeReasons.add("keyCompromise");
            config.getCrlConfigs().get(0).setOnlySomeReasons(onlySomeReasons);
            List<ExtensionConfig> extensionConfigList = config.getExtensions();
            for (ExtensionConfig extensionConfig : extensionConfigList) {
                if (extensionConfig.getExtensionId().toString().equals("2.5.29.31")) {
                    CrlDistributionPointsConfig crldpconfig = (CrlDistributionPointsConfig) extensionConfig;
                    ReasonFlags reasonFlags = new ReasonFlags("reasonFlags");
                    reasonFlags.setaACompromise(true);
                    crldpconfig.getDistributionPointList().get(0).setReasons(reasonFlags);
                }
            }

        }, testInfo);
    }
}

