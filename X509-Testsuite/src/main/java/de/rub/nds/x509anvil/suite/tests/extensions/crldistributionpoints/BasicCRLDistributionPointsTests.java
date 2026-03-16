package de.rub.nds.x509anvil.suite.tests.extensions.crldistributionpoints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.asn1.model.Asn1UniversalString;
import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.CrlDistributionPointsConfig;
import de.rub.nds.x509attacker.config.extension.InhibitAnyPolicyConfig;
import de.rub.nds.x509attacker.constants.*;
import de.rub.nds.x509attacker.x509.model.*;
import de.rub.nds.x509attacker.x509.model.extensions.DistributionPoint;
import de.rub.nds.x509attacker.x509.model.extensions.DistributionPointName;
import de.rub.nds.x509attacker.x509.model.extensions.GeneralNames;
import de.rub.nds.x509attacker.x509.model.extensions.ReasonFlags;
import org.junit.jupiter.api.TestInfo;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class BasicCRLDistributionPointsTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-0123456789")
    public void basicTest(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CrlDistributionPointsConfig crlDistributionPointsConfig = new CrlDistributionPointsConfig();
            crlDistributionPointsConfig.setPresent(true);
            crlDistributionPointsConfig.setCritical(true);
            List<DistributionPoint> distributionPointList = new ArrayList<>();
            DistributionPoint distributionPoint = new DistributionPoint("test dp");

            /*Creating a FullName*/
            /*DistributionPointName distributionPointName = new DistributionPointName("test dp");
            distributionPointName.setDistributionPointNameChoiceType(DistributionPointNameChoiceType.FULL_NAME);
            GeneralNames generalNamesForDPName = new GeneralNames("gns0:");
            List<GeneralName> generalNameListForDPName = new ArrayList<>();
            GeneralName generalNameForDPName = new GeneralName("test dp");
            generalNameForDPName.setGeneralNameChoiceTypeConfig(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER);
            generalNameForDPName.setGeneralNameConfigValue("http://localhost:8099/crls/72.crl");
            generalNameListForDPName.add(generalNameForDPName);
            generalNamesForDPName.setGeneralNames(generalNameListForDPName);
            distributionPointName.setFullName(generalNamesForDPName);
            distributionPoint.setDistributionPointName(distributionPointName);*/

            /*Creating a NameRealtiveToCRLIssuer*/
            DistributionPointName distributionPointName = new DistributionPointName("test dp");
            distributionPointName.setDistributionPointNameChoiceType(DistributionPointNameChoiceType.NAME_RELATIVE_TO_CRL_ISSUER);
            RelativeDistinguishedName relativeDistinguishedName = new RelativeDistinguishedName("test dp");
            List<AttributeTypeAndValue> attributeTypeAndValues = new ArrayList<>();
            AttributeTypeAndValue attributeTypeAndValue = new AttributeTypeAndValue("attTandV", DirectoryStringChoiceType.UTF8_STRING);
            attributeTypeAndValue.setAttributeTypeConfig(X500AttributeType.COMMON_NAME);
            DirectoryString directoryString1 = new DirectoryString("test directory string");
            Asn1Utf8String asn1Utf8String = new Asn1Utf8String("test string");
            asn1Utf8String.setValue("MrIssuerOfUniversalString");
            directoryString1.makeSelection(asn1Utf8String);
            directoryString1.setUtf8String(asn1Utf8String);
            /* second directoryString2 */
            DirectoryString directoryString2 = new DirectoryString("test directory string");
            Asn1UniversalString asn1UniversalString2 = new Asn1UniversalString("test string2");
            asn1UniversalString2.setValue("Common Name test");
            directoryString2.makeSelection(asn1UniversalString2);
            directoryString2.setUniversalString(asn1UniversalString2);
            AttributeTypeAndValue attributeTypeAndValue2 = new AttributeTypeAndValue("attTandV", DirectoryStringChoiceType.UNIVERSAL_STRING);
            attributeTypeAndValue2.setAttributeTypeConfig(X500AttributeType.ORGANISATION_NAME);
            attributeTypeAndValue2.setValue(directoryString2);
            attributeTypeAndValue.setValue(directoryString1);
            /* end second directoryString */
            attributeTypeAndValues.add(attributeTypeAndValue);
            attributeTypeAndValues.add(attributeTypeAndValue2);
            relativeDistinguishedName.setAttributeTypeAndValueList(attributeTypeAndValues);
            distributionPointName.setNameRelativeToCRLIssuer(relativeDistinguishedName);
            distributionPoint.setDistributionPointName(distributionPointName);


            GeneralNames generalNamesForIssuer = new GeneralNames("gns:");
            List<GeneralName> generalNameListForIssuer = new ArrayList<>();
            GeneralName generalNameForIssuer = new GeneralName("gn");
            ReasonFlags reasonFlags = new ReasonFlags("reasons");
            reasonFlags.setaACompromise(true);
            reasonFlags.setKeyCompromise(true);
            reasonFlags.setAffiliationChanged(true);
            generalNameForIssuer.setGeneralNameChoiceTypeConfig(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER);
            generalNameForIssuer.setGeneralNameConfigValue("http://localhost:8099/crls/72.crl");
            generalNameListForIssuer.add(generalNameForIssuer);
            generalNamesForIssuer.setGeneralNames(generalNameListForIssuer);
            distributionPoint.setCrlIssuer(generalNamesForIssuer);
            distributionPoint.setReasons(reasonFlags);
            distributionPointList.add(distributionPoint);
            crlDistributionPointsConfig.setDistributionPointList(distributionPointList);
            config.addExtensions(crlDistributionPointsConfig);
        }, testInfo);
    }
}
