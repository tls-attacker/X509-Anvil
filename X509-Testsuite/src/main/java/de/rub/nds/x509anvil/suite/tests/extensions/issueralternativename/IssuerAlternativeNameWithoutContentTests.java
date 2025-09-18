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

import java.util.List;

public class IssuerAlternativeNameWithoutContentTests extends X509AnvilTest {


    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-eb7d7b73a7")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void issuerAltNameEmptyEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(true);
            issuerAlternativeNameConfig.setCritical(false);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of());
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of());
            config.addExtensions(issuerAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-ee591d0f6d")
    public void issuerAltNameEmptyIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            IssuerAlternativeNameConfig issuerAlternativeNameConfig = new IssuerAlternativeNameConfig();
            issuerAlternativeNameConfig.setPresent(false);
            issuerAlternativeNameConfig.setCritical(true);
            issuerAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of());
            issuerAlternativeNameConfig.setGeneralNameConfigValues(List.of());
            config.addExtensions(issuerAlternativeNameConfig);
        });
    }
}
