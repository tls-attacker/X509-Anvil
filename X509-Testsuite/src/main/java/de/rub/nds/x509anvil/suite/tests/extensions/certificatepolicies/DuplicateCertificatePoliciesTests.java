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
import org.junit.jupiter.api.TestInfo;

import java.util.List;

public class DuplicateCertificatePoliciesTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-3a125b4c97")
    public void duplicateIdenticalPoliciesEntity(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
            config.addExtensions(certificatePoliciesConfig);
            config.setIncludeExtensions(true);
        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-3a126b4c97")
    public void duplicateIdenticalPoliciesIntermediate(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);
            config.addExtensions(certificatePoliciesConfig);
        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-3a127b4c97")
    public void duplicateDifferentPoliciesEntity(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);

            CertificatePoliciesConfig certificatePoliciesConfigDifferent = new CertificatePoliciesConfig();
            certificatePoliciesConfigDifferent.setPresent(true);
            certificatePoliciesConfigDifferent.setCritical(true);
            certificatePoliciesConfigDifferent.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.2"));
            certificatePoliciesConfigDifferent.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfigDifferent.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfigDifferent);
            config.setIncludeExtensions(true);
        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-3a128b4c97")
    public void duplicateDifferentPoliciesIntermediate(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfig);

            CertificatePoliciesConfig certificatePoliciesConfigDifferent = new CertificatePoliciesConfig();
            certificatePoliciesConfigDifferent.setPresent(true);
            certificatePoliciesConfigDifferent.setCritical(true);
            certificatePoliciesConfigDifferent.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.2"));
            certificatePoliciesConfigDifferent.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfigDifferent.setIncludeQualifiers(List.of(false));
            config.addExtensions(certificatePoliciesConfigDifferent);
        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-3a127b4c98")
    public void duplicateDifferentOrderPoliciesEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));

            CertificatePoliciesConfig certificatePoliciesConfigDifferent = new CertificatePoliciesConfig();
            certificatePoliciesConfigDifferent.setPresent(true);
            certificatePoliciesConfigDifferent.setCritical(true);
            certificatePoliciesConfigDifferent.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.2"));
            certificatePoliciesConfigDifferent.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfigDifferent.setIncludeQualifiers(List.of(false));

            config.addExtensions(certificatePoliciesConfigDifferent);
            config.addExtensions(certificatePoliciesConfig);

            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-3a128b4c99")
    public void duplicateDifferentOrderPoliciesIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false));

            CertificatePoliciesConfig certificatePoliciesConfigDifferent = new CertificatePoliciesConfig();
            certificatePoliciesConfigDifferent.setPresent(true);
            certificatePoliciesConfigDifferent.setCritical(true);
            certificatePoliciesConfigDifferent.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.2"));
            certificatePoliciesConfigDifferent.setPolicyQualifiers(List.of(new PolicyQualifiers("empty")));
            certificatePoliciesConfigDifferent.setIncludeQualifiers(List.of(false));

            config.addExtensions(certificatePoliciesConfigDifferent);
            config.addExtensions(certificatePoliciesConfig);
        });
    }
}
