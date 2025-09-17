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

import java.util.LinkedList;
import java.util.List;

public class SubjectAlternativeNameFormattingTests extends X509AnvilTest {


    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-f4c711dd6d" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void nonCriticalAltNameWhenEmptySubjectEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("test.com"));
            config.setSubject(new LinkedList<>());
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-53a913244e")
    public void nonCriticalAltNameWhenEmptySubjectIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("test.com"));
            config.setSubject(new LinkedList<>());
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-b85eea047f" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void subjectAltNameMailFormattingEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("mail@test.com"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-ba3c67bcf6" )
    public void subjectAltNameMailFormattingIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("mail@test.com"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-5c3703f705" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void subjectAltNameIpAddressFormattingEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of(new byte[]{0x01, 0x01, 0x01, 0x01, 0x01}));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-e6cdce436a" )
    public void subjectAltNameIpAddressFormattingIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of(new byte[]{0x01, 0x01, 0x01, 0x01, 0x01}));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-e313a21fbc" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void subjectAltNameDnsNameTypeEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of(new byte[] {0x74, 0x65, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d}));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-420b8e5ee3" )
    public void subjectAltNameDnsNameTypeIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of(new byte[] {0x74, 0x65, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d}));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-8cfafee500" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void subjectAltNameDnsNamePreferredTypeEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("test;com"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-ad3d24bfdd" )
    public void subjectAltNameDnsNamePreferredTypeIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of("test;com"));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-395bba36f0" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void subjectAltNameDnsNameEmptyEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of(" "));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-aed854dd91" )
    public void subjectAltNameDnsNameEmptyIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(false);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of(" "));
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }
}
