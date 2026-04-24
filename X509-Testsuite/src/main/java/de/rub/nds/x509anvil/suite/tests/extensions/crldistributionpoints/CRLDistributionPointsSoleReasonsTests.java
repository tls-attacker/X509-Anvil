package de.rub.nds.x509anvil.suite.tests.extensions.crldistributionpoints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.CrlDistributionPointsConfig;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.x509.model.extensions.DistributionPoint;
import de.rub.nds.x509attacker.x509.model.extensions.ReasonFlags;
import org.junit.jupiter.api.TestInfo;

import java.util.ArrayList;
import java.util.List;


public class CRLDistributionPointsSoleReasonsTests extends X509AnvilTest {
    /*
     * a DistributionPoint MUST NOT consist of only the reasons field; either distributionPoint or cRLIssuer MUST be present.
     */
    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-0123456710")
    public void basicTest(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CrlDistributionPointsConfig crlDistributionPointsConfig = new CrlDistributionPointsConfig();
            crlDistributionPointsConfig.setPresent(true);
            List<DistributionPoint> distributionPointList = new ArrayList<>();
            DistributionPoint distributionPoint = new DistributionPoint("test dp");
            distributionPoint.setDistributionPointName(null);
            distributionPoint.setCrlIssuer(null);
            ReasonFlags reasonFlags = new ReasonFlags("reasons");
            reasonFlags.setAffiliationChanged(true);
            distributionPoint.setReasons(reasonFlags);
            distributionPointList.add(distributionPoint);
            crlDistributionPointsConfig.setDistributionPointList(distributionPointList);
            List<ExtensionConfig> extensionConfigList = config.getExtensions();
            for (ExtensionConfig extensionConfig : extensionConfigList) {
                if (extensionConfig.getExtensionId().toString().equals("2.5.29.31")) {
                    ((CrlDistributionPointsConfig) extensionConfig).setDistributionPointList(distributionPointList);
                }
            }
            config.setExtensions(extensionConfigList);
        }, testInfo);
    }

}
