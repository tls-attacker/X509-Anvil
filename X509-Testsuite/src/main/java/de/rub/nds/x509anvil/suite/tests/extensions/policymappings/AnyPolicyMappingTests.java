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

public class AnyPolicyMappingTests extends X509AnvilTest {

    // When qualifiers are used with the special policy anyPolicy, they MUST be limited to the qualifiers identified in this section
    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-7b8f543a1f")
    public void anyPolicyMappingFromEntityToIssuerInEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);

            certificatePoliciesConfig.setPolicyIdentifiers(List.of("2.5.29.32.0"));

            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("qualifiers")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
            config.setIncludeExtensions(true);

            PolicyMappingsConfig policyMappingsConfig = new PolicyMappingsConfig();
            policyMappingsConfig.setPresent(true);
            policyMappingsConfig.setCritical(true);
            policyMappingsConfig.setSubjectDomainPolicies(List.of("2.5.29.32.0"));
            policyMappingsConfig.setIssuerDomainPolicies(List.of("2.23.140.1.2.1"));
            config.addExtensions(policyMappingsConfig);


        }, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);

            certificatePoliciesConfig.setPolicyIdentifiers(List.of("2.23.140.1.2.1"));

            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("qualifiers")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
        });
    }

    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength = 4)
    @AnvilTest(id = "extension-42c0e99d7d")
    public void anyPolicyMappingFromEntityToIssuerInIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);

            certificatePoliciesConfig.setPolicyIdentifiers(List.of("2.5.29.32.0"));

            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("qualifiers")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);

            PolicyMappingsConfig policyMappingsConfig = new PolicyMappingsConfig();
            policyMappingsConfig.setPresent(true);
            policyMappingsConfig.setCritical(true);
            policyMappingsConfig.setSubjectDomainPolicies(List.of("2.5.29.32.0"));
            policyMappingsConfig.setIssuerDomainPolicies(List.of("2.23.140.1.2.1"));
            config.addExtensions(policyMappingsConfig);


        }, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);

            certificatePoliciesConfig.setPolicyIdentifiers(List.of("2.23.140.1.2.1"));

            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("qualifiers")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
        });
    }

    // When qualifiers are used with the special policy anyPolicy, they MUST be limited to the qualifiers identified in this section
    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-587d94f3b5")
    public void anyPolicyMappingFromIssuerToEntityInEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);

            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("qualifiers")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
            config.setIncludeExtensions(true);

            certificatePoliciesConfig.setPolicyIdentifiers(List.of("2.23.140.1.2.1"));

            PolicyMappingsConfig policyMappingsConfig = new PolicyMappingsConfig();
            policyMappingsConfig.setPresent(true);
            policyMappingsConfig.setCritical(true);
            policyMappingsConfig.setIssuerDomainPolicies(List.of("2.5.29.32.0"));
            policyMappingsConfig.setSubjectDomainPolicies(List.of("2.23.140.1.2.1"));
            config.addExtensions(policyMappingsConfig);


        }, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);

            certificatePoliciesConfig.setPolicyIdentifiers(List.of("2.5.29.32.0"));

            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("qualifiers")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
        });
    }

    @ChainLength(minLength = 4, intermediateCertsModeled = 2, maxLength = 4)
    @AnvilTest(id = "extension-ab7837006f")
    public void anyPolicyMappingFromIssuerToEntityInIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);

            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("qualifiers")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);

            certificatePoliciesConfig.setPolicyIdentifiers(List.of("2.23.140.1.2.1"));

            PolicyMappingsConfig policyMappingsConfig = new PolicyMappingsConfig();
            policyMappingsConfig.setPresent(true);
            policyMappingsConfig.setCritical(true);
            policyMappingsConfig.setIssuerDomainPolicies(List.of("2.5.29.32.0"));
            policyMappingsConfig.setSubjectDomainPolicies(List.of("2.23.140.1.2.1"));
            config.addExtensions(policyMappingsConfig);


        }, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);

            certificatePoliciesConfig.setPolicyIdentifiers(List.of("2.5.29.32.0"));

            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("qualifiers")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
        });
    }
}
