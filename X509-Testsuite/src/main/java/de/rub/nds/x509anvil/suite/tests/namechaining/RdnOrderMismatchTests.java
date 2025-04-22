package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;

import java.util.Collections;
import java.util.List;

public class RdnOrderMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two distinguished names DN1 and DN2 match if [...] and the matching RDNs appear in the same order in both DNs")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void rdnOrderMismatch(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, config -> config.setSubject(List.of(new Pair<>(X500AttributeType.DN_QUALIFIER, "dnq"))), reverseRdnsOrderModifier());
    }

    private static X509CertificateModifier reverseRdnsOrderModifier() {
        return (certificate) -> {
            Name issuer = certificate.getTbsCertificate().getIssuer();
            List<RelativeDistinguishedName> shallowCopy = issuer.getRelativeDistinguishedNames().subList(0, issuer.getRelativeDistinguishedNames().size());
            Collections.reverse(shallowCopy);
            issuer.setRelativeDistinguishedNames(shallowCopy);
        };
    }
}
