package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.asn1.model.Asn1Ia5String;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;

public class DomainComponentCaseInsensitiveTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.3. Internationalized Domain Names in Distinguished Names",
            text = "Conforming implementations shall perform a case-insensitive exact match when comparing domainComponent " +
                    "attributes in distinguished names")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0:domain_components_present", method = "enabled")
    @AnvilTest()
    public void switchedCaseDomainComponentTest(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, domainComponentCaseSwitchModifier());
    }

    private static X509CertificateModifier domainComponentCaseSwitchModifier() {
        return (certificate) -> {
            Name issuer = certificate.getTbsCertificate().getIssuer();
            RelativeDistinguishedName rdn = X509Util.getRdnFromName(issuer, X500AttributeType.DOMAIN_COMPONENT);
            String oldName = rdn.getAttributeTypeAndValueList().get(0).getStringValueOfValue();
            Asn1Ia5String asn1PrimitiveIa5String = new Asn1Ia5String("domainComponent");
            asn1PrimitiveIa5String.setValue(oldName.toUpperCase());
            rdn.getAttributeTypeAndValueList().get(0).setValue(asn1PrimitiveIa5String);
        };
    }
}
