package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.asn1.model.Asn1PrimitiveUtf8String;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.RFC;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.config.model.DirectoryStringType;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import de.rub.nds.x509anvil.suite.tests.util.Constraints;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class AttributeTypeMismatchTests extends X509AnvilTest {

    @RFC(number = 5280, section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest(description = "CN with the same value but different types should still match")
    public void typeMismatchCn(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, nameComponentTypeSwitchModifier(AttributeTypeObjectIdentifiers.COMMON_NAME));
        Assertions.assertTrue(result.isValid());
    }

    @RFC(number = 5280, section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.nc_country_name_present", clazz = Constraints.class, method = "enabled")
    @AnvilTest(description = "Country with the same value but different types should still match")
    public void typeMismatchCountry(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, nameComponentTypeSwitchModifier(AttributeTypeObjectIdentifiers.COUNTRY_NAME));
        Assertions.assertTrue(result.isValid());
    }

    @RFC(number = 5280, section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.nc_organization_present", clazz = Constraints.class, method = "enabled")
    @AnvilTest(description = "Organization with the same value but different types should still match")
    public void typeMismatchOrganization(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, nameComponentTypeSwitchModifier(AttributeTypeObjectIdentifiers.ORGANIZATION_NAME));
        Assertions.assertTrue(result.isValid());
    }

    @RFC(number = 5280, section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.nc_organizational_unit_present", clazz = Constraints.class, method = "enabled")
    @AnvilTest(description = "OrganizationalUnit with the same value but different types should still match")
    public void typeMismatchOrganizationalUnit(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, nameComponentTypeSwitchModifier(AttributeTypeObjectIdentifiers.ORGANIZATIONAL_UNIT_NAME));
        Assertions.assertTrue(result.isValid());
    }

    @RFC(number = 5280, section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.nc_organization_present", clazz = Constraints.class, method = "enabled")
    @AnvilTest(description = "DN Qualifier with the same value but different types should still match")
    public void typeMismatchDnQualifier(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).getSubject().addNameComponent(AttributeTypeObjectIdentifiers.DN_QUALIFIER, "dnq", DirectoryStringType.PRINTABLE);
        VerifierResult result = testRunner.execute(chainConfig, nameComponentTypeSwitchModifier(AttributeTypeObjectIdentifiers.DN_QUALIFIER));
        Assertions.assertTrue(result.isValid());
    }

    @RFC(number = 5280, section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.nc_state_province_present", clazz = Constraints.class, method = "enabled")
    @AnvilTest(description = "State or Province with the same value but different types should still match")
    public void typeMismatchStateProvince(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, nameComponentTypeSwitchModifier(AttributeTypeObjectIdentifiers.STATE_OR_PROVINCE_NAME));
        Assertions.assertTrue(result.isValid());
    }

    @RFC(number = 5280, section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.nc_serial_number_present", clazz = Constraints.class, method = "enabled")
    @AnvilTest(description = "Serial number with the same value but different types should still match")
    public void typeMismatchSerialNumber(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, nameComponentTypeSwitchModifier(AttributeTypeObjectIdentifiers.SERIAL_NUMBER));
        Assertions.assertTrue(result.isValid());
    }

    private static X509CertificateModifier nameComponentTypeSwitchModifier(String oid) {
        return (certificate, config, previousConfig) -> {
            if (config.isEntity()) {
                Asn1Sequence subjectAsn1 = (Asn1Sequence) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "issuer");
                Asn1Sequence attribute = X509Util.getAttributeFromName(subjectAsn1, oid);
                if (attribute.getChildren().get(1) instanceof Asn1PrimitivePrintableString) {
                    Asn1PrimitivePrintableString printableString = (Asn1PrimitivePrintableString) attribute.getChildren().get(1);
                    attribute.getChildren().remove(1);
                    Asn1PrimitiveUtf8String utf8String = new Asn1PrimitiveUtf8String();
                    utf8String.setValue(printableString.getValue());
                    attribute.addChild(utf8String);
                }
                else if (attribute.getChildren().get(1) instanceof Asn1PrimitiveUtf8String) {
                    Asn1PrimitiveUtf8String utf8String = (Asn1PrimitiveUtf8String) attribute.getChildren().get(1);
                    attribute.getChildren().remove(1);
                    Asn1PrimitiveUtf8String printableString = new Asn1PrimitiveUtf8String();
                    printableString.setValue(utf8String.getValue());
                    attribute.addChild(printableString);
                }
                else {
                    throw new RuntimeException("Could not change name component with oid " + oid);
                }
            }
        };
    }
}
