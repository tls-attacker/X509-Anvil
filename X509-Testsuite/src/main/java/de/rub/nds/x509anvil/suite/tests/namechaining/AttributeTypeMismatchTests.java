package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import de.rub.nds.x509attacker.constants.X500AttributeType;

import java.util.ArrayList;
import java.util.List;

public class AttributeTypeMismatchTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "namechaining-be286d6c7d")
    @IpmLimitations(identifiers = "entity:cn_type")
    public void typeMismatchCn(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.COMMON_NAME, DirectoryStringChoiceType.PRINTABLE_STRING))));
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "namechaining-658c1fd3c9")
    @IpmLimitations(identifiers = "entity:cn_type")
    public void typeMismatchCountry(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.COUNTRY_NAME, DirectoryStringChoiceType.PRINTABLE_STRING))));
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "namechaining-0946a5f8e7")
    @IpmLimitations(identifiers = "entity:cn_type")
    public void typeMismatchOrganization(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.ORGANISATION_NAME, DirectoryStringChoiceType.PRINTABLE_STRING))));
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "namechaining-0be3c6ebe2")
    @IpmLimitations(identifiers = "entity:cn_type")
    public void typeMismatchOrganizationalUnit(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.ORGANISATION_UNIT_NAME, DirectoryStringChoiceType.PRINTABLE_STRING))), (X509CertificateConfigModifier) config -> {
            List<Pair<X500AttributeType, String>> subject = new ArrayList<>(config.getSubject());
            subject.add(new Pair<>(X500AttributeType.ORGANISATION_UNIT_NAME, "Test Organizational Unit"));
            config.setSubject(subject);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "namechaining-7247764279")
    @IpmLimitations(identifiers = "entity:cn_type")
    public void typeMismatchDnQualifier(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.DN_QUALIFIER, DirectoryStringChoiceType.PRINTABLE_STRING))), (X509CertificateConfigModifier) config -> {
            List<Pair<X500AttributeType, String>> subject = new ArrayList<>(config.getSubject());
            subject.add(new Pair<>(X500AttributeType.DN_QUALIFIER, "Test DN Qualifier"));
            config.setSubject(subject);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "namechaining-75f6f195a4")
    @IpmLimitations(identifiers = "entity:cn_type")
    public void typeMismatchStateProvince(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.STATE_OR_PROVINCE_NAME, DirectoryStringChoiceType.PRINTABLE_STRING))), (X509CertificateConfigModifier) config -> {
            List<Pair<X500AttributeType, String>> subject = new ArrayList<>(config.getSubject());
            subject.add(new Pair<>(X500AttributeType.STATE_OR_PROVINCE_NAME, "Test State Province"));
            config.setSubject(subject);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "namechaining-ce08905f2b")
    @IpmLimitations(identifiers = "entity:cn_type")
    public void typeMismatchSerialNumber(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, config -> config.setDivergentIssuerDirectoryStringChoices(List.of(new Pair<>(X500AttributeType.SERIAL_NUMBER, DirectoryStringChoiceType.PRINTABLE_STRING))), (X509CertificateConfigModifier) config -> {
            List<Pair<X500AttributeType, String>> subject = new ArrayList<>(config.getSubject());
            subject.add(new Pair<>(X500AttributeType.SERIAL_NUMBER, "Test Serial Number"));
            config.setSubject(subject);
        });
    }
}
