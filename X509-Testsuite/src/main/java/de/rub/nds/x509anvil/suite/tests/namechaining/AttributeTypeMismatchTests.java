package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import de.rub.nds.x509attacker.constants.X500AttributeType;

import java.util.ArrayList;
import java.util.List;

public class AttributeTypeMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @AnvilTest(id = "namechaining-5536d7084b")
    public void typeMismatchCn(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.COMMON_NAME, DirectoryStringChoiceType.PRINTABLE_STRING))));
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @AnvilTest(id = "namechaining-5536d7084b")
    public void typeMismatchCountry(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.COUNTRY_NAME, DirectoryStringChoiceType.PRINTABLE_STRING))));
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @AnvilTest(id = "namechaining-5536d7084b")
    public void typeMismatchOrganization(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.ORGANISATION_NAME, DirectoryStringChoiceType.PRINTABLE_STRING))));
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @AnvilTest(id = "namechaining-5536d7084b")
    public void typeMismatchOrganizationalUnit(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.ORGANISATION_UNIT_NAME, DirectoryStringChoiceType.PRINTABLE_STRING))), (X509CertificateConfigModifier) config -> {
            List<Pair<X500AttributeType, String>> subject = new ArrayList<>(config.getSubject());
            subject.add(new Pair<>(X500AttributeType.ORGANISATION_UNIT_NAME, "Test Organizational Unit"));
            config.setSubject(subject);
        });
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @AnvilTest(id = "namechaining-5536d7084b")
    public void typeMismatchDnQualifier(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.DN_QUALIFIER, DirectoryStringChoiceType.PRINTABLE_STRING))), (X509CertificateConfigModifier) config -> {
            List<Pair<X500AttributeType, String>> subject = new ArrayList<>(config.getSubject());
            subject.add(new Pair<>(X500AttributeType.DN_QUALIFIER, "Test DN Qualifier"));
            config.setSubject(subject);
        });
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @AnvilTest(id = "namechaining-5536d7084b")
    public void typeMismatchStateProvince(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.STATE_OR_PROVINCE_NAME, DirectoryStringChoiceType.PRINTABLE_STRING))), (X509CertificateConfigModifier) config -> {
            List<Pair<X500AttributeType, String>> subject = new ArrayList<>(config.getSubject());
            subject.add(new Pair<>(X500AttributeType.STATE_OR_PROVINCE_NAME, "Test State Province"));
            config.setSubject(subject);
        });
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Conforming implementations MUST use the LDAP StringPrep profile (including insignificant space handling), as specified in [RFC4518], " +
                    "as the basis for comparison of distinguished name attributes encoded in either PrintableString or UTF8String.")
    @SeverityLevel(Severity.ERROR)
    @AnvilTest(id = "namechaining-5536d7084b")
    public void typeMismatchSerialNumber(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.SERIAL_NUMBER, DirectoryStringChoiceType.PRINTABLE_STRING))), (X509CertificateConfigModifier) config -> {
            List<Pair<X500AttributeType, String>> subject = new ArrayList<>(config.getSubject());
            subject.add(new Pair<>(X500AttributeType.SERIAL_NUMBER, "Test Serial Number"));
            config.setSubject(subject);
        });
    }
}
