package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

public class AttributeNumberMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two relative distinguished names RDN1 and RDN2 match if they have the same number of naming attributes")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void missingAttribute(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier)  config -> {
            config.setRemoveFirstRdnIssuer(true);
        });
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two relative distinguished names RDN1 and RDN2 match if they have the same number of naming attributes")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 4, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void additionalAttribute(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier)  config -> {
            config.setDuplicateFirstRdnIssuer(true);
        });
    }
}
