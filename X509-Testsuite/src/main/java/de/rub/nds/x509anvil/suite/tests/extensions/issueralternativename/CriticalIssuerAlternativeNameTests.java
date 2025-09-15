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
import de.rub.nds.x509attacker.constants.GeneralNameChoiceType;

import java.util.List;

public class CriticalIssuerAlternativeNameTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-a4c1edb4d9")
    public void criticalIssuerAltNameEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(true);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("test.com"));
            config.addExtensions(issuerAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-b1b2cfd8d1")
    public void criticalIssuerAltNameIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(true);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of(GeneralNameChoiceType.DNS_NAME));
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of("test.com"));
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }
}
