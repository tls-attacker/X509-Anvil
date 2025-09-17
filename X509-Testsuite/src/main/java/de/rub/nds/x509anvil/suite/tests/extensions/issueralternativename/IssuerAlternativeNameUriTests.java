package de.rub.nds.x509anvil.suite.tests.extensions.issueralternativename;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.IssuerAlternativeNameConfig;
import de.rub.nds.x509attacker.constants.GeneralNameChoiceType;

import java.util.List;

public class IssuerAlternativeNameUriTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-b247cea7ca" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void issuerAltNameUriEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of(new byte[]{0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x66, 0x69, 0x6C, 0x65}));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-337825e1c7" )
    @SeverityLevel(Severity.INFORMATIONAL)
    public void issuerAltNameUriIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.IP_ADDRESS));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of(new byte[]{0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x66, 0x69, 0x6C, 0x65}));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-848691cb51" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void issuerAltNameUriRelativeEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("file"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-497dede29d" )
    @SeverityLevel(Severity.INFORMATIONAL)
    public void issuerAltNameUriRelativeIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("file"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-195bf04da5" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void issuerAltNameInvalidUriEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("https://test.com;file"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-38d4b6e6f1" )
    @SeverityLevel(Severity.INFORMATIONAL)
    public void issuerAltNameInvalidUriIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("https://test.com;file"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-8a6d852e22" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void issuerAltNameNoSchemeUriEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("test.com/file"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-f675452d31" )
    @SeverityLevel(Severity.INFORMATIONAL)
    public void issuerAltNameNoSchemeUriIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("test.com/file"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-3f9fa8cb40" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void issuerAltNameNoPathUriEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("https://"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-f7749028cf" )
    @SeverityLevel(Severity.INFORMATIONAL)
    public void issuerAltNameNoPathUriIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("https://"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-a1b27a1650" )
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void issuerAltNameAuthorityUriEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("user@test.com"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-5a2b87c1f5" )
    @SeverityLevel(Severity.INFORMATIONAL)
    public void issuerAltNameAuthorityUriIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.UNIFORM_RESOURCE_IDENTIFIER));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("user@test.com"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }
}
