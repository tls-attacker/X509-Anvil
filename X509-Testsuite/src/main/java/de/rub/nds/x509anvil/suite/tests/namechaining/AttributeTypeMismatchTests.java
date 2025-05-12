package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.asn1.model.Asn1PrintableString;
import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;

public class AttributeTypeMismatchTests extends X509AnvilTest {

    //TODO: What is the point of this?
    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void typeMismatchCn(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, nameComponentTypeSwitchModifier(X500AttributeType.COMMON_NAME));
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0:nc_country_name_present", method = "enabled")
    @AnvilTest()
    public void typeMismatchCountry(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, nameComponentTypeSwitchModifier(X500AttributeType.COUNTRY_NAME));
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0:nc_organization_present", method = "enabled")
    @AnvilTest()
    public void typeMismatchOrganization(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, nameComponentTypeSwitchModifier(X500AttributeType.ORGANISATION_NAME));
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0:nc_organizational_unit_present", method = "enabled")
    @AnvilTest()
    public void typeMismatchOrganizationalUnit(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, nameComponentTypeSwitchModifier(X500AttributeType.ORGANISATION_UNIT_NAME));
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0:nc_organization_present", method = "enabled")
    @AnvilTest()
    public void typeMismatchDnQualifier(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true,
                config -> config.getSubject().add(new Pair<>(X500AttributeType.DN_QUALIFIER, "new_dn")),
                nameComponentTypeSwitchModifier(X500AttributeType.DN_QUALIFIER));
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0:nc_state_province_present", method = "enabled")
    @AnvilTest()
    public void typeMismatchStateProvince(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, nameComponentTypeSwitchModifier(X500AttributeType.STATE_OR_PROVINCE_NAME));
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0:nc_serial_number_present", method = "enabled")
    @AnvilTest()
    public void typeMismatchSerialNumber(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, nameComponentTypeSwitchModifier(X500AttributeType.SERIAL_NUMBER));
    }

    private static X509CertificateModifier nameComponentTypeSwitchModifier(X500AttributeType oid) {
        return (certificate) -> {
            Name issuer = certificate.getTbsCertificate().getIssuer();
            RelativeDistinguishedName rdn = X509Util.getRdnFromName(issuer, oid);

            AttributeTypeAndValue attributeTypeAndValue = rdn.getAttributeTypeAndValueList().get(0);
            if (attributeTypeAndValue.getValue() instanceof Asn1PrintableString) {
                Asn1Utf8String asn1Utf8String = new Asn1Utf8String("wrong");
                asn1Utf8String.setValue(attributeTypeAndValue.getStringValueOfValue());
                attributeTypeAndValue.setValue(asn1Utf8String);
            } else if (attributeTypeAndValue.getValue() instanceof Asn1Utf8String) {
                Asn1PrintableString asn1PrintableString = new Asn1PrintableString("wrong");
                asn1PrintableString.setValue(attributeTypeAndValue.getStringValueOfValue());
                attributeTypeAndValue.setValue(asn1PrintableString);
            } else {
                throw new RuntimeException("Could not change name component with oid " + oid);
            }
        };
    }
}
