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
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import org.junit.platform.commons.JUnitException;

public class RdnStructureMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest()
    public void rdnStructureMismatch(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, mergeRdnsModifier());
    }

    private static X509CertificateModifier mergeRdnsModifier() {
        return (certificate) -> {
            Name issuer = certificate.getTbsCertificate().getIssuer();
            if (issuer.getRelativeDistinguishedNames().size() <= 1) {
                throw new JUnitException("At least 2 name components required");
            }
            RelativeDistinguishedName firstRnd = issuer.getRelativeDistinguishedNames().get(0);
            int ataaIdentifier = 1;
            for (int i = 1; i < issuer.getRelativeDistinguishedNames().size(); i++) {
                RelativeDistinguishedName rdn = issuer.getRelativeDistinguishedNames().get(i);
                for (AttributeTypeAndValue attributeTypeAndValue : rdn.getAttributeTypeAndValueList()) {
                    attributeTypeAndValue.setIdentifier("attributeTypeAndValue" + ataaIdentifier++);
                    firstRnd.addAttributeTypeAndValue(attributeTypeAndValue);
                }
            }
            issuer.getRelativeDistinguishedNames().subList(1, issuer.getRelativeDistinguishedNames().size()).clear();
        };
    }
}
