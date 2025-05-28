package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

public class AttributeNumberMismatchTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "namechaining-4075e0cc0f")
    public void missingAttribute(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier)  config -> {
            config.setRemoveFirstRdnIssuer(true);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "namechaining-5fa5031980")
    public void additionalAttribute(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier)  config -> {
            config.setDuplicateFirstRdnIssuer(true);
        });
    }
}
