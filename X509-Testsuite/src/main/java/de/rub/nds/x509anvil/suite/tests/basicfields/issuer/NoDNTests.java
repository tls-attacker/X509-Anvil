package de.rub.nds.x509anvil.suite.tests.basicfields.issuer;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

import java.util.List;

public class NoDNTests extends X509AnvilTest {

    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-21d376ecbb")
    public void noDn(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // this sets the subject of the intermediate and the issuer of the entity cert to an empty list
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setSubject(List.of()));
    }
}
