package de.rub.nds.x509anvil.suite.tests.basicfields.serialnumber;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;

public class LargeSerialNumberTest extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.2.1. Version",
            text = "Given the uniqueness requirements above, serial numbers can be expected to contain long integers.  " +
                    "Certificate users MUST be able to handle serialNumber values up to 20 octets.  Conforming CAs MUST" +
                    "NOT use serialNumber values longer than 20 octets.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "entity:serial_number")
    @AnvilTest(id = "basic-63b58d6a92")
    public void largeSerialNumberEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setSerialNumber(TestUtils.createBigInteger(256)));
    }

    @Specification(document = "RFC 5280", section = "4.1.2.1. Version",
            text = "Given the uniqueness requirements above, serial numbers can be expected to contain long integers.  " +
                    "Certificate users MUST be able to handle serialNumber values up to 20 octets.  Conforming CAs MUST" +
                    "NOT use serialNumber values longer than 20 octets.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "inter0:serial_number")
    @AnvilTest(id = "basic-c482ae3643")
    public void largeSerialNumberIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
        (X509CertificateConfigModifier) config ->
        config.setSerialNumber(TestUtils.createBigInteger(256)));
    }

}
