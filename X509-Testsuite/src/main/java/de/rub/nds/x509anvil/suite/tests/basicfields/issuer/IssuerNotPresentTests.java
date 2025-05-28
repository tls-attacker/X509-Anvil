package de.rub.nds.x509anvil.suite.tests.basicfields.issuer;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

public class IssuerNotPresentTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-3d37c180b5")
    public void noIssuerEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setIncludeIssuer(false));
   }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-3502b37055")
    public void noIssuerIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setIncludeIssuer(false));
      }
}
