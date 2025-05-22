package de.rub.nds.x509anvil.suite.tests.signature;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

public class InvalidSignatureTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "6.1.3. Basic Certificate Processing",
            text = "The signature on the certificate can be verified using working_public_key_algorithm, the working_public_key," +
                    " and the working_public_key_parameters.")
    @SeverityLevel(Severity.CRITICAL)
    @AnvilTest
    public void invalidSignatureEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setSignatureInvalid(true));
    }

    @Specification(document = "RFC 5280", section = "6.1.3. Basic Certificate Processing",
            text = "The signature on the certificate can be verified using working_public_key_algorithm, the working_public_key," +
                    " and the working_public_key_parameters.")
    @SeverityLevel(Severity.CRITICAL)
    @AnvilTest
    public void invalidSignatureIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> config.setSignatureInvalid(true));
    }
}
