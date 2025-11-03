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

import java.util.List;

public class SubjectAlternativeNameUriTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-c7bcd39697" )
    @IpmLimitations(identifiers = { "entity:extensions_present", "entity:ext_subject_alt_name_present", "entity:ext_subject_alt_name_values" })
    public void subjectAltNameUriEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of(new byte[]{0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x66, 0x69, 0x6C, 0x65}));
            config.addExtensions(subjectAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-485a129c88" )
    @IpmLimitations(identifiers = { "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values" })
    public void subjectAltNameUriIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of(new byte[]{0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x66, 0x69, 0x6C, 0x65}));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-4a67c83ba5" )
    @IpmLimitations(identifiers = { "entity:extensions_present", "entity:ext_subject_alt_name_present", "entity:ext_subject_alt_name_values" })
    public void subjectAltNameUriRelativeEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("file"));
            config.addExtensions(subjectAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-b2a952d256" )
    @IpmLimitations(identifiers = { "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values" })
    public void subjectAltNameUriRelativeIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("file"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-755f6f9a73" )
    @IpmLimitations(identifiers = { "entity:extensions_present", "entity:ext_subject_alt_name_present", "entity:ext_subject_alt_name_values" })
    public void subjectAltNameInvalidUriEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("https://tls-attacker.com;file"));
            config.addExtensions(subjectAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-90276bbd2e" )
    @IpmLimitations(identifiers = { "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values" })
    public void subjectAltNameInvalidUriIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("https://tls-attacker.com;file"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-1de992c455" )
    @IpmLimitations(identifiers = { "entity:extensions_present", "entity:ext_subject_alt_name_present", "entity:ext_subject_alt_name_values" })
    public void subjectAltNameNoSchemeUriEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com/file"));
            config.addExtensions(subjectAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-5e7399fe45" )
    @IpmLimitations(identifiers = { "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values" })
    public void subjectAltNameNoSchemeUriIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("tls-attacker.com/file"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-6abf32243f" )
    @IpmLimitations(identifiers = { "entity:extensions_present", "entity:ext_subject_alt_name_present", "entity:ext_subject_alt_name_values" })
    public void subjectAltNameNoPathUriEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("https://"));
            config.addExtensions(subjectAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-c6ff9d3f5f" )
    @IpmLimitations(identifiers = { "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values" })
    public void subjectAltNameNoPathUriIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("https://"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-0710a73747" )
    @IpmLimitations(identifiers = { "entity:extensions_present", "entity:ext_subject_alt_name_present", "entity:ext_subject_alt_name_values" })
    public void subjectAltNameAuthorityUriEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("user@tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-2be00fdc1f" )
    @IpmLimitations(identifiers = { "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values" })
    public void subjectAltNameAuthorityUriIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("user@tls-attacker.com"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }
}
