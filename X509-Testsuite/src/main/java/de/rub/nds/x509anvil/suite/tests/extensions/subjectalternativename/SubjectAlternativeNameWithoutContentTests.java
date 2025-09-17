package de.rub.nds.x509anvil.suite.tests.extensions.subjectalternativename;

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
import de.rub.nds.x509attacker.config.extension.SubjectAlternativeNameConfig;

import java.util.List;

public class SubjectAlternativeNameWithoutContentTests extends X509AnvilTest {


    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-c1b1cda8d9")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void subjectAltNameEmptyEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(true);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of());
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of());
            config.addExtensions(subjectAlternativeNameConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-a8b5caa8d9")
    @SeverityLevel(Severity.INFORMATIONAL)
    public void subjectAltNameEmptyIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectAlternativeNameConfig subjectAlternativeNameConfig = new SubjectAlternativeNameConfig();
            subjectAlternativeNameConfig.setPresent(true);
            subjectAlternativeNameConfig.setCritical(true);
            subjectAlternativeNameConfig.setGeneralNameChoiceTypeConfigs(List.of());
            subjectAlternativeNameConfig.setGeneralNameConfigValues(List.of());
            config.addExtensions(subjectAlternativeNameConfig);
        });
    }
}
