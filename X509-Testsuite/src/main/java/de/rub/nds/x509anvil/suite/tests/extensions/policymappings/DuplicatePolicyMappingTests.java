package de.rub.nds.x509anvil.suite.tests.extensions.policymappings;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.CertificatePoliciesConfig;
import de.rub.nds.x509attacker.config.extension.PolicyMappingsConfig;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyQualifiers;

import java.util.List;

public class DuplicatePolicyMappingTests extends X509AnvilTest {
    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-72af503a1f")
    public void duplicateIdenticalPolicyMappingsEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);

            PolicyMappingsConfig policyMappingsConfig = new PolicyMappingsConfig();
            policyMappingsConfig.setPresent(true);
            policyMappingsConfig.setCritical(true);
            policyMappingsConfig.setSubjectDomainPolicies(List.of("1.3.6.1.5.5.7.2.1"));
            policyMappingsConfig.setIssuerDomainPolicies(List.of("1.3.6.1.5.5.7.2.2"));
            config.addExtensions(policyMappingsConfig);
            config.addExtensions(policyMappingsConfig);

            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.2"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
        });
    }

    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength = 4)
    @AnvilTest(id = "extension-72af513a1f")
    public void duplicateIdenticalPolicyMappingsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);

            PolicyMappingsConfig policyMappingsConfig = new PolicyMappingsConfig();
            policyMappingsConfig.setPresent(true);
            policyMappingsConfig.setCritical(true);
            policyMappingsConfig.setSubjectDomainPolicies(List.of("1.3.6.1.5.5.7.2.1"));
            policyMappingsConfig.setIssuerDomainPolicies(List.of("1.3.6.1.5.5.7.2.2"));
            config.addExtensions(policyMappingsConfig);
            config.addExtensions(policyMappingsConfig);
        }, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.2"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
        });
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-72af523a1f")
    public void duplicateDifferentPolicyMappingsEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);

            PolicyMappingsConfig policyMappingsConfig = new PolicyMappingsConfig();
            policyMappingsConfig.setPresent(true);
            policyMappingsConfig.setCritical(true);
            policyMappingsConfig.setSubjectDomainPolicies(List.of("1.3.6.1.5.5.7.2.1"));
            policyMappingsConfig.setIssuerDomainPolicies(List.of("1.3.6.1.5.5.7.2.2"));
            config.addExtensions(policyMappingsConfig);

            PolicyMappingsConfig policyMappingsConfigDifferent = new PolicyMappingsConfig();
            policyMappingsConfigDifferent.setPresent(true);
            policyMappingsConfigDifferent.setCritical(true);
            policyMappingsConfigDifferent.setSubjectDomainPolicies(List.of("1.3.6.1.5.5.7.2.1"));
            policyMappingsConfigDifferent.setIssuerDomainPolicies(List.of("1.3.6.1.5.5.7.2.3"));
            config.addExtensions(policyMappingsConfigDifferent);

            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.2"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
        });
    }

    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength = 4)
    @AnvilTest(id = "extension-72af533a1f")
    public void duplicateDifferentPolicyMappingsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);

            PolicyMappingsConfig policyMappingsConfig = new PolicyMappingsConfig();
            policyMappingsConfig.setPresent(true);
            policyMappingsConfig.setCritical(true);
            policyMappingsConfig.setSubjectDomainPolicies(List.of("1.3.6.1.5.5.7.2.1"));
            policyMappingsConfig.setIssuerDomainPolicies(List.of("1.3.6.1.5.5.7.2.2"));
            config.addExtensions(policyMappingsConfig);

            PolicyMappingsConfig policyMappingsConfigDifferent = new PolicyMappingsConfig();
            policyMappingsConfigDifferent.setPresent(true);
            policyMappingsConfigDifferent.setCritical(true);
            policyMappingsConfigDifferent.setSubjectDomainPolicies(List.of("1.3.6.1.5.5.7.2.1"));
            policyMappingsConfigDifferent.setIssuerDomainPolicies(List.of("1.3.6.1.5.5.7.2.3"));
            config.addExtensions(policyMappingsConfigDifferent);
        }, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.2"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
        });
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-72af523a2e")
    public void duplicateDifferentOrderPolicyMappingsEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);

            PolicyMappingsConfig policyMappingsConfig = new PolicyMappingsConfig();
            policyMappingsConfig.setPresent(true);
            policyMappingsConfig.setCritical(true);
            policyMappingsConfig.setSubjectDomainPolicies(List.of("1.3.6.1.5.5.7.2.1"));
            policyMappingsConfig.setIssuerDomainPolicies(List.of("1.3.6.1.5.5.7.2.2"));

            PolicyMappingsConfig policyMappingsConfigDifferent = new PolicyMappingsConfig();
            policyMappingsConfigDifferent.setPresent(true);
            policyMappingsConfigDifferent.setCritical(true);
            policyMappingsConfigDifferent.setSubjectDomainPolicies(List.of("1.3.6.1.5.5.7.2.1"));
            policyMappingsConfigDifferent.setIssuerDomainPolicies(List.of("1.3.6.1.5.5.7.2.3"));

            config.addExtensions(policyMappingsConfigDifferent);
            config.addExtensions(policyMappingsConfig);

            config.setIncludeExtensions(true);
        }, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.2"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
        });
    }

    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength = 4)
    @AnvilTest(id = "extension-72af533a3e")
    public void duplicateDifferentOrderPolicyMappingsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);

            PolicyMappingsConfig policyMappingsConfig = new PolicyMappingsConfig();
            policyMappingsConfig.setPresent(true);
            policyMappingsConfig.setCritical(true);
            policyMappingsConfig.setSubjectDomainPolicies(List.of("1.3.6.1.5.5.7.2.1"));
            policyMappingsConfig.setIssuerDomainPolicies(List.of("1.3.6.1.5.5.7.2.2"));

            PolicyMappingsConfig policyMappingsConfigDifferent = new PolicyMappingsConfig();
            policyMappingsConfigDifferent.setPresent(true);
            policyMappingsConfigDifferent.setCritical(true);
            policyMappingsConfigDifferent.setSubjectDomainPolicies(List.of("1.3.6.1.5.5.7.2.1"));
            policyMappingsConfigDifferent.setIssuerDomainPolicies(List.of("1.3.6.1.5.5.7.2.3"));

            config.addExtensions(policyMappingsConfigDifferent);
            config.addExtensions(policyMappingsConfig);
        }, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.2"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
        });
    }
}
