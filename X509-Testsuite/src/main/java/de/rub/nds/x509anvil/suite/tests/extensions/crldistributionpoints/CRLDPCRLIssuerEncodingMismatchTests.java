package de.rub.nds.x509anvil.suite.tests.extensions.crldistributionpoints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.asn1.model.Asn1PrintableString;
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
import de.rub.nds.x509attacker.x509.model.extensions.GeneralNames;
import org.junit.jupiter.api.TestInfo;

import java.util.ArrayList;
import java.util.List;

public class CRLDPCRLIssuerEncodingMismatchTests extends X509AnvilTest {
    /*
     * The encoding of the name in the cRLIssuer field MUST be exactly the same
     * as the encoding in the issuer field of the CRL.
     */
    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-crldp-s9-1")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void basicTest(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            config.getCrlConfigs().get(0).setRootAsIssuer(true);
            GeneralNames crlIssuer = new GeneralNames("general Names");
            List<GeneralName> crlIssuerList = new ArrayList<>();
            GeneralName generalNameForIssuer = new GeneralName("GeneralName");

            generalNameForIssuer.setGeneralNameChoiceTypeConfig(GeneralNameChoiceType.DIRECTORY_NAME);
            Name nameModel = new Name("nameModel", NameType.GENERAL_NAME);
            List<RelativeDistinguishedName> relativeDistinguishedNameList = new ArrayList<>();

            RelativeDistinguishedName cnRdn = new RelativeDistinguishedName("cn rdn");
            List<AttributeTypeAndValue> cnAtts = new ArrayList<>();
            AttributeTypeAndValue commonNameAttribute = new AttributeTypeAndValue("commonName", DirectoryStringChoiceType.PRINTABLE_STRING);
            commonNameAttribute.setAttributeTypeConfig(X500AttributeType.COMMON_NAME);
            Asn1PrintableString cnPrintable = new Asn1PrintableString("cnPrintable");
            cnPrintable.setValue("TLS-Attacker");
            DirectoryString cnDirectoryString = new DirectoryString("cn directory string");
            cnDirectoryString.makeSelection(cnPrintable);
            cnDirectoryString.setPrintableString(cnPrintable);
            commonNameAttribute.setValue(cnDirectoryString);
            cnAtts.add(commonNameAttribute);
            cnRdn.setAttributeTypeAndValueList(cnAtts);

            RelativeDistinguishedName orgRdn = new RelativeDistinguishedName("org rdn");
            List<AttributeTypeAndValue> orgAtts = new ArrayList<>();
            AttributeTypeAndValue orgAttribute = new AttributeTypeAndValue("org", DirectoryStringChoiceType.PRINTABLE_STRING);
            orgAttribute.setAttributeTypeConfig(X500AttributeType.ORGANISATION_NAME);
            Asn1PrintableString orgPrintable = new Asn1PrintableString("orgPrintable");
            orgPrintable.setValue("TLS Attacker CA - Global Insecurity Provider");
            DirectoryString orgDirectoryString = new DirectoryString("org directory string");
            orgDirectoryString.makeSelection(orgPrintable);
            orgDirectoryString.setPrintableString(orgPrintable);
            orgAttribute.setValue(orgDirectoryString);
            orgAtts.add(orgAttribute);
            orgRdn.setAttributeTypeAndValueList(orgAtts);

            RelativeDistinguishedName countryRdn = new RelativeDistinguishedName("country rdn");
            List<AttributeTypeAndValue> countryAtts = new ArrayList<>();
            AttributeTypeAndValue countryAttribute = new AttributeTypeAndValue("country", DirectoryStringChoiceType.PRINTABLE_STRING);
            countryAttribute.setAttributeTypeConfig(X500AttributeType.COUNTRY_NAME);
            Asn1PrintableString countryPrintable = new Asn1PrintableString("countryPrintable");
            countryPrintable.setValue("Global");
            DirectoryString countryDirectoryString = new DirectoryString("country directory string");
            countryDirectoryString.makeSelection(countryPrintable);
            countryDirectoryString.setPrintableString(countryPrintable);
            countryAttribute.setValue(countryDirectoryString);
            countryAtts.add(countryAttribute);
            countryRdn.setAttributeTypeAndValueList(countryAtts);

            relativeDistinguishedNameList.add(countryRdn);
            relativeDistinguishedNameList.add(orgRdn);
            relativeDistinguishedNameList.add(cnRdn);
            nameModel.setRelativeDistinguishedNames(relativeDistinguishedNameList);
            generalNameForIssuer.setGeneralNameConfigValue(nameModel);

            crlIssuerList.add(generalNameForIssuer);
            crlIssuer.setGeneralNames(crlIssuerList);

            List<ExtensionConfig> extensionConfigList = config.getExtensions();
            for (int i = extensionConfigList.size() - 1; i >= 0; i--) {
                ExtensionConfig extensionConfig = extensionConfigList.get(i);
                if (extensionConfig.getExtensionId().toString().equals("2.5.29.31")) {
                    ((CrlDistributionPointsConfig) extensionConfig)
                            .getDistributionPointList().get(0).setCrlIssuer(crlIssuer);
                }
            }

        }, testInfo);
    }
}