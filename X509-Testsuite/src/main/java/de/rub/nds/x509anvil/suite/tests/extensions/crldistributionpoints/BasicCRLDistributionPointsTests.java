package de.rub.nds.x509anvil.suite.tests.extensions.crldistributionpoints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.InhibitAnyPolicyConfig;
import de.rub.nds.x509attacker.config.extension.CRLDistributionPointsConfig;
import de.rub.nds.x509attacker.constants.GeneralNameChoiceType;
import de.rub.nds.x509attacker.x509.model.GeneralName;
import de.rub.nds.x509attacker.x509.model.extensions.DistributionPoint;
import de.rub.nds.x509attacker.x509.model.extensions.DistributionPointName;
import de.rub.nds.x509attacker.x509.model.extensions.GeneralNames;

import java.util.ArrayList;
import java.util.List;

public class BasicCRLDistributionPointsTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-0123456789")
    public void basicTest(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> {

            CRLDistributionPointsConfig crlDistributionPointsConfig = new CRLDistributionPointsConfig();
            crlDistributionPointsConfig.setPresent(true);
            crlDistributionPointsConfig.setCritical(true);
            List<DistributionPoint> distributionPointList = new ArrayList<>();
            DistributionPoint distributionPoint = new DistributionPoint("test dp");
            GeneralNames generalNames = new GeneralNames("gns:");
            List<GeneralName> generalNameList = new ArrayList<>();
            GeneralName generalName = new GeneralName("gn");
            generalName.setGeneralNameChoiceTypeConfig(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER);
            generalName.setGeneralNameConfigValue("http://e8.c.lencr.org/72.crl");
            generalNameList.add(generalName);
            generalNames.setGeneralNames(generalNameList);
            distributionPoint.setCrlIssuer(generalNames);
            distributionPointList.add(distributionPoint);
            crlDistributionPointsConfig.setDistributionPointList(distributionPointList);
            config.addExtensions(crlDistributionPointsConfig);
        });
    }
}
