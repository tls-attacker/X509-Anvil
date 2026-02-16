package de.rub.nds.x509anvil.suite.tests.extensions.freshestcrl;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.CrlDistributionPointsConfig;
import de.rub.nds.x509attacker.config.extension.FreshestCrlConfig;
import de.rub.nds.x509attacker.constants.GeneralNameChoiceType;
import de.rub.nds.x509attacker.x509.model.GeneralName;
import de.rub.nds.x509attacker.x509.model.extensions.DistributionPoint;
import de.rub.nds.x509attacker.x509.model.extensions.GeneralNames;
import org.junit.jupiter.api.TestInfo;
import java.util.ArrayList;
import java.util.List;

public class BasicFreshestCrlTests  extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-0123456780")
    public void basicTest(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> {
            FreshestCrlConfig freshestCrlConfig = new FreshestCrlConfig();
            freshestCrlConfig.setPresent(true);
            freshestCrlConfig.setCritical(true);
            List<DistributionPoint> distributionPointList = new ArrayList<>();
            DistributionPoint distributionPoint = new DistributionPoint("test dp");
            GeneralNames generalNames = new GeneralNames("gns:");
            List<GeneralName> generalNameList = new ArrayList<>();
            GeneralName generalName = new GeneralName("gn");
            generalName.setGeneralNameChoiceTypeConfig(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER);
            generalName.setGeneralNameConfigValue("http://localhost:8099/crls/72.crl");
            generalNameList.add(generalName);
            generalNames.setGeneralNames(generalNameList);
            distributionPoint.setCrlIssuer(generalNames);
            distributionPointList.add(distributionPoint);
            freshestCrlConfig.setDistributionPointList(distributionPointList);
            config.addExtensions(freshestCrlConfig);
        }, testInfo);
    }
}
