package de.rub.nds.x509anvil.suite.tests.extensions.policymappings;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.PolicyMappingsConfig;

import java.util.List;

public class NonCriticalPolicyMappingsTests extends X509AnvilTest {
    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-12c3ea29d2")
    public void nonCriticalPolicyMappingsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            PolicyMappingsConfig policyMappingsConfig = new PolicyMappingsConfig();
            policyMappingsConfig.setPresent(true);
            policyMappingsConfig.setCritical(false);
            policyMappingsConfig.setIssuerDomainPolicies(List.of("2.23.140.1.2.1", "2.23.140.1.2.2"));
            policyMappingsConfig.setSubjectDomainPolicies(List.of("2.23.140.1.2.1", "2.23.140.1.2.2"));
            config.addExtensions(policyMappingsConfig);
        });
    }
}
