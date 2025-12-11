package de.rub.nds.x509anvil.suite.tests.extensions.inhibitanypolicy;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.InhibitAnyPolicyConfig;

public class DuplicateInhibitAnyPolicyTests extends X509AnvilTest {
    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-799e5cd501")
    public void duplicateIdenticalInhibitAnyPolicyIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            InhibitAnyPolicyConfig inhibitAnyPolicyConfig = new InhibitAnyPolicyConfig();
            inhibitAnyPolicyConfig.setPresent(true);
            inhibitAnyPolicyConfig.setCritical(true);
            inhibitAnyPolicyConfig.setSkipCerts(2);
            config.addExtensions(inhibitAnyPolicyConfig);
            config.addExtensions(inhibitAnyPolicyConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-799e5cd511")
    public void duplicateDifferentInhibitAnyPolicyIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            InhibitAnyPolicyConfig inhibitAnyPolicyConfig = new InhibitAnyPolicyConfig();
            inhibitAnyPolicyConfig.setPresent(true);
            inhibitAnyPolicyConfig.setCritical(true);
            inhibitAnyPolicyConfig.setSkipCerts(2);
            config.addExtensions(inhibitAnyPolicyConfig);

            InhibitAnyPolicyConfig inhibitAnyPolicyConfigDifferent = new InhibitAnyPolicyConfig();
            inhibitAnyPolicyConfigDifferent.setPresent(true);
            inhibitAnyPolicyConfigDifferent.setCritical(true);
            inhibitAnyPolicyConfigDifferent.setSkipCerts(3);
            config.addExtensions(inhibitAnyPolicyConfigDifferent);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-799e5cd512")
    public void duplicateDifferentOrderInhibitAnyPolicyIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            InhibitAnyPolicyConfig inhibitAnyPolicyConfig = new InhibitAnyPolicyConfig();
            inhibitAnyPolicyConfig.setPresent(true);
            inhibitAnyPolicyConfig.setCritical(true);
            inhibitAnyPolicyConfig.setSkipCerts(2);

            InhibitAnyPolicyConfig inhibitAnyPolicyConfigDifferent = new InhibitAnyPolicyConfig();
            inhibitAnyPolicyConfigDifferent.setPresent(true);
            inhibitAnyPolicyConfigDifferent.setCritical(true);
            inhibitAnyPolicyConfigDifferent.setSkipCerts(3);

            config.addExtensions(inhibitAnyPolicyConfigDifferent);
            config.addExtensions(inhibitAnyPolicyConfig);
        });
    }
}
