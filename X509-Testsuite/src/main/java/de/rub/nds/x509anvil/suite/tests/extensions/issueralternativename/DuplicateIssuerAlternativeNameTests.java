package de.rub.nds.x509anvil.suite.tests.extensions.issueralternativename;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.IssuerAlternativeNameConfig;
import de.rub.nds.x509attacker.config.extension.SubjectAlternativeNameConfig;
import de.rub.nds.x509attacker.constants.GeneralNameChoiceType;

import java.util.List;

public class DuplicateIssuerAlternativeNameTests extends X509AnvilTest {
    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-91b57700be" )
    @IpmLimitations(identifiers = { "entity:extensions_present", "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values", "entity:ext_subject_alt_name_present", "entity:ext_subject_alt_name_values" })
    public void duplicateIdenticalIssuerAlternativeNameEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(issuerAlternativeNameConfig);
            config.addExtensions(issuerAlternativeNameConfig);
            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength = 4)
    @AnvilTest(id = "extension-91b57710be")
    @IpmLimitations(identifiers = { "inter1:ext_subject_alt_name_present", "inter1:ext_subject_alt_name_values", "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values" })
    public void duplicateIdenticalIssuerAlternativeNameIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(issuerAlternativeNameConfig);
            config.addExtensions(issuerAlternativeNameConfig);

        }, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-91b57720be" )
    @IpmLimitations(identifiers = { "entity:extensions_present", "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values", "entity:ext_subject_alt_name_present", "entity:ext_subject_alt_name_values" })
    public void duplicateDifferentIssuerAlternativeNameEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(issuerAlternativeNameConfig);

            IssuerAlternativeNameConfig issuerAlternativeNameConfigDifferent = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfigDifferent.setPresent(true);
            issuerAlternativeNameConfigDifferent.setCritical(false);
            issuerAlternativeNameConfigDifferent.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfigDifferent.setGeneralNameConfigValues(List.of("www.tls-attacker.com"));
            config.addExtensions(issuerAlternativeNameConfigDifferent);
            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength = 4)
    @AnvilTest(id = "extension-91b57730be")
    @IpmLimitations(identifiers = { "inter1:ext_subject_alt_name_present", "inter1:ext_subject_alt_name_values", "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values" })
    public void duplicateDifferentIssuerAlternativeNameIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(issuerAlternativeNameConfig);

            IssuerAlternativeNameConfig issuerAlternativeNameConfigDifferent = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfigDifferent.setPresent(true);
            issuerAlternativeNameConfigDifferent.setCritical(false);
            issuerAlternativeNameConfigDifferent.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfigDifferent.setGeneralNameConfigValues(List.of("www.tls-attacker.com"));
            config.addExtensions(issuerAlternativeNameConfigDifferent);

        }, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-91b57720bf" )
    @IpmLimitations(identifiers = { "entity:extensions_present", "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values", "entity:ext_subject_alt_name_present", "entity:ext_subject_alt_name_values" })
    public void duplicateDifferentOrderIssuerAlternativeNameEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));

            IssuerAlternativeNameConfig issuerAlternativeNameConfigDifferent = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfigDifferent.setPresent(true);
            issuerAlternativeNameConfigDifferent.setCritical(false);
            issuerAlternativeNameConfigDifferent.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfigDifferent.setGeneralNameConfigValues(List.of("www.tls-attacker.com"));

            config.addExtensions(issuerAlternativeNameConfigDifferent);
            config.addExtensions(issuerAlternativeNameConfig);

            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength = 4)
    @AnvilTest(id = "extension-91b57730ff")
    @IpmLimitations(identifiers = { "inter1:ext_subject_alt_name_present", "inter1:ext_subject_alt_name_values", "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values" })
    public void duplicateDifferentOrderIssuerAlternativeNameIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));

            IssuerAlternativeNameConfig issuerAlternativeNameConfigDifferent = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfigDifferent.setPresent(true);
            issuerAlternativeNameConfigDifferent.setCritical(false);
            issuerAlternativeNameConfigDifferent.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfigDifferent.setGeneralNameConfigValues(List.of("www.tls-attacker.com"));

            config.addExtensions(issuerAlternativeNameConfigDifferent);
            config.addExtensions(issuerAlternativeNameConfig);

        }, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }
}
