package de.rub.nds.x509anvil.suite.tests.namechaining;

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
import de.rub.nds.x509attacker.x509.model.Name;

import static de.rub.nds.x509anvil.framework.x509.config.X509Util.addDnQualifierToName;

public class RdnNumberMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two distinguished names DN1 and DN2 match if they have the same number of RDNs")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void missingRdn(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        //TODO: Missing not correclty implemented
        assertInvalid(testRunner, true, missingRdnModifier());
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two distinguished names DN1 and DN2 match if they have the same number of RDNs")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void additionalRdn(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, additionalRdnModifier());
    }

    //TODO: Missing not correclty implemented
    // Ads an additional "distinguished name qualifier" to the intermediate's subject
    private static X509CertificateModifier missingRdnModifier() {
        return (certificate) -> {
            Name subject = certificate.getTbsCertificate().getSubject();
            addDnQualifierToName(subject);
        };
    }

    // Ads an additional "distinguished name qualifier" to the entity's issuer
    private static X509CertificateModifier additionalRdnModifier() {
        return (certificate) -> {
            Name issuer = certificate.getTbsCertificate().getIssuer();
            addDnQualifierToName(issuer);
        };
    }
}
