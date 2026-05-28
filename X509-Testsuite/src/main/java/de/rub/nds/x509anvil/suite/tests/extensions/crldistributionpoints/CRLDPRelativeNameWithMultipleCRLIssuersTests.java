package de.rub.nds.x509anvil.suite.tests.extensions.crldistributionpoints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.asn1.model.Asn1Utf8String;
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

public class CRLDPRelativeNameWithMultipleCRLIssuersTests extends X509AnvilTest {
    /*
     * The DistributionPointName MUST NOT use the nameRelativeToCRLIssuer
     * alternative when cRLIssuer contains more than one distinguished name.
     */
    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-0123456718")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void basicTest(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {

            List<ExtensionConfig> extensionConfigList = config.getExtensions();
            for (int i = extensionConfigList.size() - 1; i >= 0; i--) {
                ExtensionConfig extensionConfig = extensionConfigList.get(i);
                if (extensionConfig.getExtensionId().toString().equals("2.5.29.31")) {
                    CrlDistributionPointsConfig crldpconfig =
                            (CrlDistributionPointsConfig) extensionConfig;

                    // Set nameRelativeToCRLIssuer as the distribution point name
                    DistributionPoint dp =
                            crldpconfig.getDistributionPointList().get(0);
                    DistributionPointName dpn = new DistributionPointName("dpn");
                    dpn.setDistributionPointNameChoiceType(
                            DistributionPointNameChoiceType.NAME_RELATIVE_TO_CRL_ISSUER);
                    RelativeDistinguishedName rdn =
                            new RelativeDistinguishedName("rdn");
                    List<AttributeTypeAndValue> atts = new ArrayList<>();
                    AttributeTypeAndValue att =
                            new AttributeTypeAndValue("cn",
                                    DirectoryStringChoiceType.UTF8_STRING);
                    att.setAttributeTypeConfig(X500AttributeType.COMMON_NAME);
                    Asn1Utf8String utf8 = new Asn1Utf8String("cnUTF8");
                    utf8.setValue("CRL Fragment");
                    DirectoryString ds = new DirectoryString("ds");
                    ds.makeSelection(utf8);
                    ds.setUtf8String(utf8);
                    att.setValue(ds);
                    atts.add(att);
                    rdn.setAttributeTypeAndValueList(atts);
                    dpn.setNameRelativeToCRLIssuer(rdn);
                    dp.setDistributionPointName(dpn);

                    // Set cRLIssuer with two distinct GeneralNames
                    GeneralNames crlIssuer = new GeneralNames("crlIssuer");
                    List<GeneralName> crlIssuerList = new ArrayList<>();

                    // First name
                    GeneralName gn1 = new GeneralName("gn1");
                    gn1.setGeneralNameChoiceTypeConfig(
                            GeneralNameChoiceType.DIRECTORY_NAME);
                    Name name1 = new Name("name1", NameType.GENERAL_NAME);
                    List<RelativeDistinguishedName> rdns1 = new ArrayList<>();
                    RelativeDistinguishedName rdn1 =
                            new RelativeDistinguishedName("rdn1");
                    List<AttributeTypeAndValue> atts1 = new ArrayList<>();
                    AttributeTypeAndValue att1 =
                            new AttributeTypeAndValue("cn1",
                                    DirectoryStringChoiceType.UTF8_STRING);
                    att1.setAttributeTypeConfig(X500AttributeType.COMMON_NAME);
                    Asn1Utf8String utf8_1 = new Asn1Utf8String("cn1UTF8");
                    utf8_1.setValue("CRL Issuer One");
                    DirectoryString ds1 = new DirectoryString("ds1");
                    ds1.makeSelection(utf8_1);
                    ds1.setUtf8String(utf8_1);
                    att1.setValue(ds1);
                    atts1.add(att1);
                    rdn1.setAttributeTypeAndValueList(atts1);
                    rdns1.add(rdn1);
                    name1.setRelativeDistinguishedNames(rdns1);
                    gn1.setGeneralNameConfigValue(name1);

                    // Second name
                    GeneralName gn2 = new GeneralName("gn2");
                    gn2.setGeneralNameChoiceTypeConfig(
                            GeneralNameChoiceType.DIRECTORY_NAME);
                    Name name2 = new Name("name2", NameType.GENERAL_NAME);
                    List<RelativeDistinguishedName> rdns2 = new ArrayList<>();
                    RelativeDistinguishedName rdn2 =
                            new RelativeDistinguishedName("rdn2");
                    List<AttributeTypeAndValue> atts2 = new ArrayList<>();
                    AttributeTypeAndValue att2 =
                            new AttributeTypeAndValue("cn2",
                                    DirectoryStringChoiceType.UTF8_STRING);
                    att2.setAttributeTypeConfig(X500AttributeType.COMMON_NAME);
                    Asn1Utf8String utf8_2 = new Asn1Utf8String("cn2UTF8");
                    utf8_2.setValue("CRL Issuer Two");
                    DirectoryString ds2 = new DirectoryString("ds2");
                    ds2.makeSelection(utf8_2);
                    ds2.setUtf8String(utf8_2);
                    att2.setValue(ds2);
                    atts2.add(att2);
                    rdn2.setAttributeTypeAndValueList(atts2);
                    rdns2.add(rdn2);
                    name2.setRelativeDistinguishedNames(rdns2);
                    gn2.setGeneralNameConfigValue(name2);

                    crlIssuerList.add(gn1);
                    crlIssuerList.add(gn2);
                    crlIssuer.setGeneralNames(crlIssuerList);
                    dp.setCrlIssuer(crlIssuer);
                }
            }
        }, testInfo);
    }
}