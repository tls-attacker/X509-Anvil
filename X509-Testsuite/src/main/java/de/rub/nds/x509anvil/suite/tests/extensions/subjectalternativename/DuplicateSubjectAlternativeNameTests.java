package de.rub.nds.x509anvil.suite.tests.extensions.subjectalternativename;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.SubjectAlternativeNameConfig;
import de.rub.nds.x509attacker.constants.GeneralNameChoiceType;
import org.junit.jupiter.api.TestInfo;

import java.util.List;

public class DuplicateSubjectAlternativeNameTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-f4c401dd6d" )
    @IpmLimitations(identifiers = { "entity:extensions_present", "entity:ext_subject_alt_name_present", "entity:ext_subject_alt_name_values" })
    public void duplicateIdenticalSubjectAlternativeNameEntity(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfig);
            config.addExtensions(subjectAlternativeNameConfig);
            config.setIncludeExtensions(true);
        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-f4c411dd6d")
    @IpmLimitations(identifiers = { "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values" })
    public void duplicateIdenticalSubjectAlternativeNameIntermediate(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfig);
            config.addExtensions(subjectAlternativeNameConfig);
        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-f4c421dd6d" )
    @IpmLimitations(identifiers = { "entity:extensions_present", "entity:ext_subject_alt_name_present", "entity:ext_subject_alt_name_values" })
    public void duplicateDifferentSubjectAlternativeNameEntity(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfig);

            SubjectAlternativeNameConfig subjectAlternativeNameConfigDifferent = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfigDifferent.setPresent(true);
            subjectAlternativeNameConfigDifferent.setCritical(false);
            subjectAlternativeNameConfigDifferent.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfigDifferent.setGeneralNameConfigValues(List.of("www.tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfigDifferent);

            config.setIncludeExtensions(true);
        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-f4c431dd6d")
    @IpmLimitations(identifiers = { "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values" })
    public void duplicateDifferentSubjectAlternativeNameIntermediate(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfig);

            SubjectAlternativeNameConfig subjectAlternativeNameConfigDifferent = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfigDifferent.setPresent(true);
            subjectAlternativeNameConfigDifferent.setCritical(false);
            subjectAlternativeNameConfigDifferent.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfigDifferent.setGeneralNameConfigValues(List.of("www.tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfigDifferent);
        }, testInfo);
    }
}
