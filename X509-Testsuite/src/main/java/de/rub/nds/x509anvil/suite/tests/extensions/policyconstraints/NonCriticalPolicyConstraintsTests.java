package de.rub.nds.x509anvil.suite.tests.extensions.policyconstraints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.PolicyConstraintsConfig;

public class NonCriticalPolicyConstraintsTests extends X509AnvilTest {

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-c5a7d132d9")
    public void nonCriticalPolicyConstraintsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            PolicyConstraintsConfig policyConstraintsConfig = new PolicyConstraintsConfig();
            policyConstraintsConfig.setPresent(true);
            policyConstraintsConfig.setCritical(false);
            policyConstraintsConfig.setIncludeRequired(true);
            policyConstraintsConfig.setIncludeRequired(true);
            policyConstraintsConfig.setSkipCertsInhibit(3);
            policyConstraintsConfig.setSkipCertsRequired(10);
            config.addExtensions(policyConstraintsConfig);
        });
    }
}
