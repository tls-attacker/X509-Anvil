package de.rub.nds.x509anvil.suite.tests.chain;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;


public class SelfSignedNonRootTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "chain-1694cbbbbf")
    public void selfSignedEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier)config -> config.setSelfSigned(true));
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "chain-01967f3251")
    public void selfSignedIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier)config -> config.setSelfSigned(true));
    }

}
