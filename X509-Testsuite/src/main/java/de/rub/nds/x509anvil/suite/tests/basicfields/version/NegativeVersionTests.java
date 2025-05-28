package de.rub.nds.x509anvil.suite.tests.basicfields.version;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

import java.math.BigInteger;

public class NegativeVersionTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-d196ac0293")
    @IpmLimitations(identifiers = "entity:version")
    public void negativeVersionEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true,
        (X509CertificateConfigModifier) config -> config.setVersion(BigInteger.valueOf(-1)));
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-04db02edb2")
    @IpmLimitations(identifiers = "inter0:version")
    public void negativeVersionIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
        (X509CertificateConfigModifier) config -> config.setVersion(BigInteger.valueOf(-1)));
    }
}
