package de.rub.nds.x509anvil.suite.tests.extensions.nameconstraints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.NameConstraintsConfig;

public class EmptyNameConstraintsTests extends X509AnvilTest {
    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-a6c2a465a3")
    public void nonCriticalNameConstraintsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            NameConstraintsConfig nameConstraintsConfig = new NameConstraintsConfig();
            nameConstraintsConfig.setPresent(true);
            nameConstraintsConfig.setCritical(false);
            config.addExtensions(nameConstraintsConfig);
        });
    }
}
