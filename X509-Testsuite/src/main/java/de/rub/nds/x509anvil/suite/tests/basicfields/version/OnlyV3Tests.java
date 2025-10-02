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

public class OnlyV3Tests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-a3e135eba6")
    @IpmLimitations(identifiers = "entity:version")
    public void v1Entity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier) config -> config.setVersion(BigInteger.valueOf(0)));
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-a6a825cba3")
    @IpmLimitations(identifiers = "inter0:version")
    public void v1Intermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier) config -> config.setVersion(BigInteger.valueOf(0)));
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-a9e117aba9")
    @IpmLimitations(identifiers = "entity:version")
    public void v2Entity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier) config -> config.setVersion(BigInteger.valueOf(1)));
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-c9a8351ca3")
    @IpmLimitations(identifiers = "inter0:version")
    public void v2Intermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier) config -> config.setVersion(BigInteger.valueOf(1)));
    }
}
