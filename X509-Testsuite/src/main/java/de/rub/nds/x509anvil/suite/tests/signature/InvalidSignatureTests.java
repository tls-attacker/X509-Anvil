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
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;

public class InvalidSignatureTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "6.1.3. Basic Certificate Processing",
            text = "The signature on the certificate can be verified using working_public_key_algorithm, the working_public_key," +
                    " and the working_public_key_parameters.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void invalidSignatureEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateModifier) certificate -> {
            //TODO: Changes get overwritten
            certificate.getSignature().getContent().getValue()[32] = (byte) (~certificate.getSignature().getContent().getValue()[32] & 0xFF);
            byte[] wrongSignature = certificate.getSignatureComputations().getSignatureBytes().getValue();
            wrongSignature[32]  = (byte) (~wrongSignature[32] & 0xFF);
            certificate.getSignatureComputations().setSignatureBytes(wrongSignature);
        });
    }

    @Specification(document = "RFC 5280", section = "6.1.3. Basic Certificate Processing",
            text = "The signature on the certificate can be verified using working_public_key_algorithm, the working_public_key," +
                    " and the working_public_key_parameters.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void invalidSignatureIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        //TODO: Changes get overwritten
        assertInvalid(testRunner, false, (X509CertificateModifier) certificate -> {
            certificate.getSignature().getContent().getValue()[32] = (byte) (~certificate.getSignature().getContent().getValue()[32] & 0xFF);
        });
    }
}
