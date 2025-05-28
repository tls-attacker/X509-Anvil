package de.rub.nds.x509anvil.suite.tests.chain;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

import java.math.BigInteger;

public class Version1IntermediateCertTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "chain-24e3a47439")
    public void version1Intermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            config.setVersion(new BigInteger("0"));
            config.setIncludeExtensions(false);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "chain-60a9344ec7")
    public void version2Intermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            config.setVersion(new BigInteger("1"));
            config.setIncludeExtensions(false);
        });
    }
}
