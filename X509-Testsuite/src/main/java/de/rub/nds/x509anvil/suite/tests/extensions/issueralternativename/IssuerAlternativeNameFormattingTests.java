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

import java.util.LinkedList;
import java.util.List;

public class IssuerAlternativeNameFormattingTests extends X509AnvilTest {

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-91b57880be" )
    @IpmLimitations(identifiers = { "entity:extensions_present", "inter0:ext_subject_alt_name_present", "inter0:ext_subject_alt_name_values" })
    public void nonCriticalAltNameWhenEmptySubjectEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("test.com"));
            config.addExtensions(issuerAlternativeNameConfig);
            config.setIssuer(new LinkedList<>());
            config.setFixIssuer(true);
            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("test.com"));
            config.addExtensions(subjectAlternativeNameConfig);
            config.setSubject(new LinkedList<>());
        });
    }

    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength = 4)
    @AnvilTest(id = "extension-68c93d34e9")
    @IpmLimitations(identifiers = { "inter1:ext_subject_alt_name_present", "inter1:ext_subject_alt_name_values" })
    public void nonCriticalAltNameWhenEmptySubjectIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("test.com"));
            config.addExtensions(issuerAlternativeNameConfig);
            config.setIssuer(new LinkedList<>());
            config.setFixIssuer(true);
        }, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("test.com"));
            config.addExtensions(subjectAlternativeNameConfig);
            config.setSubject(new LinkedList<>());
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-fd6f7e2ec8" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void issuerAltNameMailFormattingEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("mail@test.com"));
            config.addExtensions(issuerAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-df9c7bd48a" )
    public void issuerAltNameMailFormattingIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("mail@test.com"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-9a8cfa3dcc" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void issuerAltNameIpAddressFormattingEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of(new byte[]{0x01, 0x01, 0x01, 0x01, 0x01}));
            config.addExtensions(issuerAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-72d58e9202" )
    public void issuerAltNameIpAddressFormattingIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of(new byte[]{0x01, 0x01, 0x01, 0x01, 0x01}));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    // When the issuerAltName extension contains a domain name system label, the domain name MUST be stored in the dNSName
    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-d943626982" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void issuerAltNameDnsNameTypeEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of(new byte[] {0x74, 0x65, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d}));
            config.addExtensions(issuerAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-8a26a71fc0" )
    public void issuerAltNameDnsNameTypeIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of(new byte[] {0x74, 0x65, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d}));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-c199210ef3" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void issuerAltNameDnsNamePreferredTypeEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("test;com"));
            config.addExtensions(issuerAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-c4f9120a7d" )
    public void issuerAltNameDnsNamePreferredTypeIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("test;com"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-75fc92cadc" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void issuerAltNameDnsNameEmptyEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of(" "));
            config.addExtensions(issuerAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-e4e530c1ca" )
    public void issuerAltNameDnsNameEmptyIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of(" "));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }
}
