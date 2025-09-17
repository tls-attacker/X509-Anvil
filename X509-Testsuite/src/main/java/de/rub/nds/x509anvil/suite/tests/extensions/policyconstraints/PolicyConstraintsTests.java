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

public class PolicyConstraintsTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-515bf6be01")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void mustAcceptPolicyConstraintsEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true, (X509CertificateConfigModifier) config -> {
            PolicyConstraintsConfig policyConstraintsConfig = new PolicyConstraintsConfig();
            policyConstraintsConfig.setPresent(true);
            policyConstraintsConfig.setCritical(true);
            policyConstraintsConfig.setIncludeInhibit(false);
            policyConstraintsConfig.setIncludeRequired(true);
            policyConstraintsConfig.setSkipCertsRequired(10);
            config.addExtensions(policyConstraintsConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-ad71b692af")
    public void mustAcceptPolicyConstraintsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, false, (X509CertificateConfigModifier) config -> {
            PolicyConstraintsConfig policyConstraintsConfig = new PolicyConstraintsConfig();
            policyConstraintsConfig.setPresent(true);
            policyConstraintsConfig.setCritical(true);
            policyConstraintsConfig.setIncludeInhibit(false);
            policyConstraintsConfig.setIncludeRequired(true);
            policyConstraintsConfig.setSkipCertsRequired(10);
            config.addExtensions(policyConstraintsConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-77b24ac4ff")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void emptyPolicyConstraintsEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            PolicyConstraintsConfig policyConstraintsConfig = new PolicyConstraintsConfig();
            policyConstraintsConfig.setPresent(true);
            policyConstraintsConfig.setCritical(true);
            policyConstraintsConfig.setIncludeInhibit(false);
            policyConstraintsConfig.setIncludeRequired(false);
            config.addExtensions(policyConstraintsConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-b7dc0826ae")
    public void emptyPolicyConstraintsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            PolicyConstraintsConfig policyConstraintsConfig = new PolicyConstraintsConfig();
            policyConstraintsConfig.setPresent(true);
            policyConstraintsConfig.setCritical(true);
            policyConstraintsConfig.setIncludeInhibit(false);
            policyConstraintsConfig.setIncludeRequired(false);
            config.addExtensions(policyConstraintsConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-6b9aabb935")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void criticalPolicyConstraintsEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            PolicyConstraintsConfig policyConstraintsConfig = new PolicyConstraintsConfig();
            policyConstraintsConfig.setPresent(true);
            policyConstraintsConfig.setCritical(false);
            policyConstraintsConfig.setIncludeInhibit(false);
            policyConstraintsConfig.setIncludeRequired(true);
            policyConstraintsConfig.setSkipCertsRequired(10);
            config.addExtensions(policyConstraintsConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-ece1272184")
    public void criticalPolicyConstraintsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            PolicyConstraintsConfig policyConstraintsConfig = new PolicyConstraintsConfig();
            policyConstraintsConfig.setPresent(true);
            policyConstraintsConfig.setCritical(false);
            policyConstraintsConfig.setIncludeInhibit(false);
            policyConstraintsConfig.setIncludeRequired(true);
            policyConstraintsConfig.setSkipCertsRequired(10);
            config.addExtensions(policyConstraintsConfig);
            config.setIncludeExtensions(true);
        });
    }
}
