package de.rub.nds.x509anvil.suite.tests.extensions.crldistributionpoints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.asn1.model.Asn1PrintableString;
import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.CrlDistributionPointsConfig;
import de.rub.nds.x509attacker.constants.*;
import de.rub.nds.x509attacker.x509.model.*;
import de.rub.nds.x509attacker.x509.model.extensions.DistributionPoint;
import de.rub.nds.x509attacker.x509.model.extensions.DistributionPointName;
import de.rub.nds.x509attacker.x509.model.extensions.GeneralNames;
import de.rub.nds.x509attacker.x509.model.extensions.ReasonFlags;
import org.junit.jupiter.api.TestInfo;

import java.util.ArrayList;
import java.util.List;

public class CRLDPCertIssuerCRLIssuerTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-0123456711")
    public void basicTest(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CrlDistributionPointsConfig crlDistributionPointsConfig = new CrlDistributionPointsConfig();
            crlDistributionPointsConfig.setPresent(true);
            List<DistributionPoint> distributionPointList = new ArrayList<>();
            DistributionPoint distributionPoint = new DistributionPoint("test dp");

            DistributionPointName distributionPointName = new DistributionPointName("dpn");
            distributionPointName.setDistributionPointNameChoiceType(DistributionPointNameChoiceType.FULL_NAME);
            GeneralNames generalNamesForDPName = new GeneralNames("gns0:");
            List<GeneralName> generalNameListForDPName = new ArrayList<>();
            GeneralName generalNameForDPName = new GeneralName("test dp");
            generalNameForDPName.setGeneralNameChoiceTypeConfig(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER);
            generalNameForDPName.setGeneralNameConfigValue("http://172.17.0.1:8099/crls/72.crl");
            generalNameListForDPName.add(generalNameForDPName);
            generalNamesForDPName.setGeneralNames(generalNameListForDPName);
            distributionPointName.setFullName(generalNamesForDPName);
            distributionPoint.setDistributionPointName(distributionPointName);

            //
            GeneralNames crlIssuer = new GeneralNames("general Names");
            List<GeneralName> crlIssuerList = new ArrayList<>();
            GeneralName generalName = new GeneralName("GeneralName");


            generalName.setGeneralNameChoiceTypeConfig(GeneralNameChoiceType.DIRECTORY_NAME);
            Name nameModel = new Name("nameModel", NameType.GENERAL_NAME);
            List<RelativeDistinguishedName> relativeDistinguishedNameList = new ArrayList<>();

            RelativeDistinguishedName cnRdn = new RelativeDistinguishedName("cn rdn");
            List<AttributeTypeAndValue> cnAtts = new ArrayList<>();
            AttributeTypeAndValue commonNameAttribute = new AttributeTypeAndValue("commonName", DirectoryStringChoiceType.UTF8_STRING);
            commonNameAttribute.setAttributeTypeConfig(X500AttributeType.COMMON_NAME);
            Asn1Utf8String cnAsn1Utf8String = new Asn1Utf8String("commonNameUTF8");
            cnAsn1Utf8String.setValue("E8");
            DirectoryString cnDirectoryString = new DirectoryString("cn directory string");
            cnDirectoryString.makeSelection(cnAsn1Utf8String);
            cnDirectoryString.setUtf8String(cnAsn1Utf8String);
            commonNameAttribute.setValue(cnDirectoryString);
            cnAtts.add(commonNameAttribute);
            cnRdn.setAttributeTypeAndValueList(cnAtts);

            RelativeDistinguishedName orgRdn = new RelativeDistinguishedName("org rdn");
            List<AttributeTypeAndValue> orgAtts = new ArrayList<>();
            AttributeTypeAndValue orgAttribute = new AttributeTypeAndValue("org", DirectoryStringChoiceType.UTF8_STRING);
            orgAttribute.setAttributeTypeConfig(X500AttributeType.ORGANISATION_NAME);
            Asn1Utf8String orgAsn1Utf8String = new Asn1Utf8String("commonNameUTF8");
            orgAsn1Utf8String.setValue("Let's Encrypt");
            DirectoryString orgDirectoryString = new DirectoryString("org directory string");
            orgDirectoryString.makeSelection(orgAsn1Utf8String);
            orgDirectoryString.setUtf8String(orgAsn1Utf8String);
            orgAttribute.setValue(orgDirectoryString);
            orgAtts.add(orgAttribute);
            orgRdn.setAttributeTypeAndValueList(orgAtts);

            RelativeDistinguishedName countryRdn = new RelativeDistinguishedName("country rdn");
            List<AttributeTypeAndValue> countryAtts = new ArrayList<>();
            AttributeTypeAndValue countryAttribute = new AttributeTypeAndValue("country", DirectoryStringChoiceType.UTF8_STRING);
            countryAttribute.setAttributeTypeConfig(X500AttributeType.COUNTRY_NAME);
            Asn1PrintableString asn1PrintableString = new Asn1PrintableString("commonNameUTF8");
            asn1PrintableString.setValue("DE");
            DirectoryString countryDirectoryString = new DirectoryString("country directory string");
            countryDirectoryString.makeSelection(asn1PrintableString);
            countryDirectoryString.setPrintableString(asn1PrintableString);
            countryAttribute.setValue(countryDirectoryString);
            countryAtts.add(countryAttribute);
            countryRdn.setAttributeTypeAndValueList(countryAtts);

            relativeDistinguishedNameList.add(countryRdn);
            relativeDistinguishedNameList.add(orgRdn);
            relativeDistinguishedNameList.add(cnRdn);
            nameModel.setRelativeDistinguishedNames(relativeDistinguishedNameList);
            //generalName.makeSelection(nameModel);
            generalName.setGeneralNameConfigValue(nameModel);

            crlIssuerList.add(generalName);
            crlIssuer.setGeneralNames(crlIssuerList);
            distributionPoint.setCrlIssuer(crlIssuer);
            //

            distributionPoint.setReasons(null);
            distributionPointList.add(distributionPoint);
            crlDistributionPointsConfig.setDistributionPointList(distributionPointList);
            config.addExtensions(crlDistributionPointsConfig);
        }, testInfo);
    }

}