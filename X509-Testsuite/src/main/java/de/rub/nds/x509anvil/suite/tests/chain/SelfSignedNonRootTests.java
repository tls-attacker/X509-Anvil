package de.rub.nds.x509anvil.suite.tests.chain;

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


public class SelfSignedNonRootTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "6.1 Basic Path Validation",
            text = "for all x in {1, ..., n-1}, the subject of certificate x is the issuer of certificate x+1;")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void selfSignedEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier)config -> config.setSelfSigned(true));
    }

    @Specification(document = "RFC 5280", section = "6.1 Basic Path Validation",
            text = "for all x in {1, ..., n-1}, the subject of certificate x is the issuer of certificate x+1;")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void selfSignedIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier)config -> config.setSelfSigned(true));
    }

}
