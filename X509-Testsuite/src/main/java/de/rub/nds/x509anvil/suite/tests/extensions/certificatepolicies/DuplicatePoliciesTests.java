package de.rub.nds.x509anvil.suite.tests.extensions.certificatepolicies;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.CertificatePoliciesConfig;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyQualifiers;

import java.util.List;

public class DuplicatePoliciesTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-cb233ef8a5")
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
    @AnvilTest(id = "extension-bc135fe2a1")
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
}
