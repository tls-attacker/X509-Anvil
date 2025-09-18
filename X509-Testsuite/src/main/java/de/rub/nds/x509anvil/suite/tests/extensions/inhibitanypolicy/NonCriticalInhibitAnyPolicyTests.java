package de.rub.nds.x509anvil.suite.tests.extensions.inhibitanypolicy;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.InhibitAnyPolicyConfig;

public class NonCriticalInhibitAnyPolicyTests extends X509AnvilTest {
    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-799e5cd831")
    public void criticalIssuerAltNameIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            InhibitAnyPolicyConfig inhibitAnyPolicyConfig = new InhibitAnyPolicyConfig();
            inhibitAnyPolicyConfig.setPresent(true);
            inhibitAnyPolicyConfig.setCritical(false);
            inhibitAnyPolicyConfig.setSkipCerts(2);
            config.addExtensions(inhibitAnyPolicyConfig);
        });
    }
}
