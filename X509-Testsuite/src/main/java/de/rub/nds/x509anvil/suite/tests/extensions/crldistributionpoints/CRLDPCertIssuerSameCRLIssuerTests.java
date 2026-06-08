package de.rub.nds.x509anvil.suite.tests.extensions.crldistributionpoints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.asn1.model.Asn1PrintableString;
import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.CrlDistributionPointsConfig;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.constants.*;
import de.rub.nds.x509attacker.x509.model.*;
import de.rub.nds.x509attacker.x509.model.extensions.DistributionPoint;
import de.rub.nds.x509attacker.x509.model.extensions.DistributionPointName;
import de.rub.nds.x509attacker.x509.model.extensions.GeneralNames;
import org.junit.jupiter.api.TestInfo;

import java.util.ArrayList;
import java.util.List;

public class CRLDPCertIssuerSameCRLIssuerTests extends X509AnvilTest {
    /*
    * If the certificate issuer is also the CRL issuer, then conforming CAs MUST omit the cRLIssuer field and MUST include the distributionPoint field
    */
    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-crldp-s3-1")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void basicTest(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            String issuerCN = "";
            String issuerOrg = "";
            String issuerCountry = "";
            for (Pair<X500AttributeType,String> pair : config.getDefaultIssuer()){
                if(pair.getKey()==X500AttributeType.COMMON_NAME){
                    issuerCN = pair.getValue();
                } else if (pair.getKey()==X500AttributeType.COUNTRY_NAME) {
                    issuerCountry = pair.getValue();
                }else if(pair.getKey()==X500AttributeType.ORGANISATION_NAME){
                    issuerOrg = pair.getValue();
                }
            }

            //
            GeneralNames crlIssuer = new GeneralNames("general Names");
            List<GeneralName> crlIssuerList = new ArrayList<>();
            GeneralName generalNameForIssuer = new GeneralName("GeneralName");


            generalNameForIssuer.setGeneralNameChoiceTypeConfig(GeneralNameChoiceType.DIRECTORY_NAME);
            Name nameModel = new Name("nameModel", NameType.GENERAL_NAME);
            List<RelativeDistinguishedName> relativeDistinguishedNameList = new ArrayList<>();

            RelativeDistinguishedName cnRdn = new RelativeDistinguishedName("issuerCN rdn");
            List<AttributeTypeAndValue> cnAtts = new ArrayList<>();
            AttributeTypeAndValue commonNameAttribute = new AttributeTypeAndValue("commonName", DirectoryStringChoiceType.UTF8_STRING);
            commonNameAttribute.setAttributeTypeConfig(X500AttributeType.COMMON_NAME);
            Asn1Utf8String cnAsn1Utf8String = new Asn1Utf8String("commonNameUTF8");
            cnAsn1Utf8String.setValue(issuerCN);
            DirectoryString cnDirectoryString = new DirectoryString("issuerCN directory string");
            cnDirectoryString.makeSelection(cnAsn1Utf8String);
            cnDirectoryString.setUtf8String(cnAsn1Utf8String);
            commonNameAttribute.setValue(cnDirectoryString);
            cnAtts.add(commonNameAttribute);
            cnRdn.setAttributeTypeAndValueList(cnAtts);

            RelativeDistinguishedName orgRdn = new RelativeDistinguishedName("issuerOrg rdn");
            List<AttributeTypeAndValue> orgAtts = new ArrayList<>();
            AttributeTypeAndValue orgAttribute = new AttributeTypeAndValue("org", DirectoryStringChoiceType.UTF8_STRING);
            orgAttribute.setAttributeTypeConfig(X500AttributeType.ORGANISATION_NAME);
            Asn1Utf8String orgAsn1Utf8String = new Asn1Utf8String("orgUTF8");
            orgAsn1Utf8String.setValue(issuerOrg);
            DirectoryString orgDirectoryString = new DirectoryString("issuerOrg directory string");
            orgDirectoryString.makeSelection(orgAsn1Utf8String);
            orgDirectoryString.setUtf8String(orgAsn1Utf8String);
            orgAttribute.setValue(orgDirectoryString);
            orgAtts.add(orgAttribute);
            orgRdn.setAttributeTypeAndValueList(orgAtts);

            RelativeDistinguishedName countryRdn = new RelativeDistinguishedName("issuerCountry rdn");
            List<AttributeTypeAndValue> countryAtts = new ArrayList<>();
            AttributeTypeAndValue countryAttribute = new AttributeTypeAndValue("issuerCountry", DirectoryStringChoiceType.PRINTABLE_STRING);
            countryAttribute.setAttributeTypeConfig(X500AttributeType.COUNTRY_NAME);
            Asn1PrintableString asn1PrintableString = new Asn1PrintableString("commonNameUTF8");
            asn1PrintableString.setValue(issuerCountry);
            DirectoryString countryDirectoryString = new DirectoryString("issuerCountry directory string");
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
            generalNameForIssuer.setGeneralNameConfigValue(nameModel);

            crlIssuerList.add(generalNameForIssuer);
            crlIssuer.setGeneralNames(crlIssuerList);

            List<ExtensionConfig> extensionConfigList = config.getExtensions();
            for (int i = extensionConfigList.size() - 1; i >= 0; i--) {
                ExtensionConfig extensionConfig = extensionConfigList.get(i);
                if (extensionConfig.getExtensionId().toString().equals("2.5.29.31")) {
                    ((CrlDistributionPointsConfig)extensionConfig).getDistributionPointList().get(0).setCrlIssuer(crlIssuer);
                }
            }

        }, testInfo);
    }

}