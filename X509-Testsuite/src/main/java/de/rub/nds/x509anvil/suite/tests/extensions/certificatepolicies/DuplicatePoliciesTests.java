package de.rub.nds.x509anvil.suite.tests.extensions.certificatepolicies;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.CertificatePoliciesConfig;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyQualifierInfo;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyQualifiers;

import java.util.List;

public class DuplicatePoliciesTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-6b125b4c97")
    public void duplicatePoliciesEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1", "1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty"), new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false, false));
            config.addExtensions(certificatePoliciesConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-c3e50f1c30")
    public void duplicatePoliciesIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1", "1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty"), new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false, false));
            config.addExtensions(certificatePoliciesConfig);
        });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-bf8b1694b7")
    public void undefinedAnyPolicyEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);

            certificatePoliciesConfig.setPolicyIdentifiers(List.of("2.5.29.32.0"));

            PolicyQualifiers qualifiers = new PolicyQualifiers("qualifiers");
            PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo("info");
            policyQualifierInfo.setPolicyObjectIdentifier(new ObjectIdentifier(new byte[] { 1, 3, 6, 1, 5, 5, 7, 2, 1 }));
            policyQualifierInfo.setQualifierOctetString(new byte[] {1, 2, 3, 4});
            qualifiers.setPolicyQualifierInfo(List.of(policyQualifierInfo));


            certificatePoliciesConfig.setPolicyQualifiers(List.of(qualifiers));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(true));
            config.addExtensions(certificatePoliciesConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-bada689d12")
    public void undefinedAnyPolicyIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("2.5.29.32.0"));

            PolicyQualifiers qualifiers = new PolicyQualifiers("qualifiers");
            PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo("info");
            policyQualifierInfo.setPolicyObjectIdentifier(new ObjectIdentifier(new byte[] { 1, 3, 6, 1, 5, 5, 7, 2, 1 }));
            policyQualifierInfo.setQualifierOctetString(new byte[] {1, 2, 3, 4});
            qualifiers.setPolicyQualifierInfo(List.of(policyQualifierInfo));


            certificatePoliciesConfig.setPolicyQualifiers(List.of(qualifiers));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(true));
            config.addExtensions(certificatePoliciesConfig);
            config.setIncludeExtensions(true);
        });
    }

    // TODO: usernotice MUST statement
}
