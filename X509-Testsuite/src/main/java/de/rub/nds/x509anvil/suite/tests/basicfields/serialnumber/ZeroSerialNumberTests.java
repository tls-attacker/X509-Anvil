package de.rub.nds.x509anvil.suite.tests.basicfields.serialnumber;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

import java.math.BigInteger;

public class ZeroSerialNumberTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:serial_number")
    @AnvilTest(id = "basic-0dd1f8b33d")
    public void zeroSerialNumberEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, true,
                (X509CertificateConfigModifier) config -> config.setSerialNumber(BigInteger.valueOf(0)));
    }


    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:serial_number")
    @AnvilTest(id = "basic-55a018dc6c")
    public void zeroSerialNumberIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, false,
                (X509CertificateConfigModifier) config -> config.setSerialNumber(BigInteger.valueOf(0)));
    }


}
