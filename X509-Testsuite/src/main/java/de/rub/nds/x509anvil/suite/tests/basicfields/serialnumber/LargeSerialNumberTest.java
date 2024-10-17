package de.rub.nds.x509anvil.suite.tests.basicfields.serialnumber;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class LargeSerialNumberTest extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.2.1. Version",
            text = "The serial number MUST be a positive integer assigned by the CA to each certificate. [...] Note: Non-conforming CAs may " +
                    "issue certificates with serial numbers that are negative or zero.  Certificate users SHOULD be prepared to " +
                    "gracefully handle such certificates.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "entity.serial_number")
    @AnvilTest
     public void largeSerialNumberEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(argumentsAccessor, testRunner, true, (X509CertificateConfigModifier) config -> config.setSerialNumber(TestUtils.createBigInteger(256)));
    }

    @Specification(document = "RFC 5280", section = "4.1.2.1. Version",
            text = "The serial number MUST be a positive integer assigned by the CA to each certificate. [...] Note: Non-conforming CAs may " +
                    "issue certificates with serial numbers that are negative or zero.  Certificate users SHOULD be prepared to " +
                    "gracefully handle such certificates.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "inter0.serial_number")
    @AnvilTest
    public void largeSerialNumberIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(argumentsAccessor, testRunner, false,
        (X509CertificateConfigModifier) config ->
        config.setSerialNumber(TestUtils.createBigInteger(256)));
    }

}
