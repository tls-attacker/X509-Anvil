package de.rub.nds.x509anvil.suite.tests.extensions.policyconstraints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.PolicyConstraintsConfig;

public class DuplicatePolicyConstraintsTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-520bf6e001")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void duplicateIdenticalPolicyConstraintsEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> {
            PolicyConstraintsConfig policyConstraintsConfig = new PolicyConstraintsConfig();
            policyConstraintsConfig.setPresent(true);
            policyConstraintsConfig.setCritical(true);
            policyConstraintsConfig.setIncludeInhibit(false);
            policyConstraintsConfig.setIncludeRequired(true);
            policyConstraintsConfig.setSkipCertsRequired(10);
            config.addExtensions(policyConstraintsConfig);
            config.addExtensions(policyConstraintsConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-521bf6e001")
    public void duplicateIdenticalPolicyConstraintsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, false, (X509CertificateConfigModifier) config -> {
            PolicyConstraintsConfig policyConstraintsConfig = new PolicyConstraintsConfig();
            policyConstraintsConfig.setPresent(true);
            policyConstraintsConfig.setCritical(true);
            policyConstraintsConfig.setIncludeInhibit(false);
            policyConstraintsConfig.setIncludeRequired(true);
            policyConstraintsConfig.setSkipCertsRequired(10);
            config.addExtensions(policyConstraintsConfig);
            config.addExtensions(policyConstraintsConfig);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-522bf6e001")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void duplicateDifferentPolicyConstraintsEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> {
            PolicyConstraintsConfig policyConstraintsConfig = new PolicyConstraintsConfig();
            policyConstraintsConfig.setPresent(true);
            policyConstraintsConfig.setCritical(true);
            policyConstraintsConfig.setIncludeInhibit(false);
            policyConstraintsConfig.setIncludeRequired(true);
            policyConstraintsConfig.setSkipCertsRequired(10);
            config.addExtensions(policyConstraintsConfig);

            PolicyConstraintsConfig policyConstraintsConfigDifferent = new PolicyConstraintsConfig();
            policyConstraintsConfigDifferent.setPresent(true);
            policyConstraintsConfigDifferent.setCritical(true);
            policyConstraintsConfigDifferent.setIncludeInhibit(false);
            policyConstraintsConfigDifferent.setIncludeRequired(true);
            policyConstraintsConfigDifferent.setSkipCertsRequired(5);
            config.addExtensions(policyConstraintsConfigDifferent);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-523bf6e001")
    public void duplicateDifferentPolicyConstraintsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, false, (X509CertificateConfigModifier) config -> {
            PolicyConstraintsConfig policyConstraintsConfig = new PolicyConstraintsConfig();
            policyConstraintsConfig.setPresent(true);
            policyConstraintsConfig.setCritical(true);
            policyConstraintsConfig.setIncludeInhibit(false);
            policyConstraintsConfig.setIncludeRequired(true);
            policyConstraintsConfig.setSkipCertsRequired(10);
            config.addExtensions(policyConstraintsConfig);
            config.addExtensions(policyConstraintsConfig);

            PolicyConstraintsConfig policyConstraintsConfigDifferent = new PolicyConstraintsConfig();
            policyConstraintsConfigDifferent.setPresent(true);
            policyConstraintsConfigDifferent.setCritical(true);
            policyConstraintsConfigDifferent.setIncludeInhibit(false);
            policyConstraintsConfigDifferent.setIncludeRequired(true);
            policyConstraintsConfigDifferent.setSkipCertsRequired(5);
            config.addExtensions(policyConstraintsConfigDifferent);
        });
    }
}
