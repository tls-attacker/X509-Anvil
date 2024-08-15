package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.asn1.model.*;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class AttributeNumberMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two relative distinguished names RDN1 and RDN2 match if they have the same number of naming attributes")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void missingAttribute(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(argumentsAccessor, testRunner, false, missingAttributeModifier());
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two relative distinguished names RDN1 and RDN2 match if they have the same number of naming attributes")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void additionalAttribute(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(argumentsAccessor, testRunner, false, additionalAttributeModifier());
    }

    // Ads an additional "distinguished name qualifier" to the intermediate's subject
    private static X509CertificateModifier missingAttributeModifier() {
        return (certificate) -> {
            Name subject = certificate.getTbsCertificate().getSubject();
            RelativeDistinguishedName cnRdn = X509Util.getRdnFromName(subject, AttributeTypeObjectIdentifiers.COMMON_NAME);
            addAttributeToCn(cnRdn);
        };
    }

    // Ads an additional "distinguished name qualifier" to the entity's issuer
    private static X509CertificateModifier additionalAttributeModifier() {
        return (certificate) -> {
            Name issuer = certificate.getTbsCertificate().getIssuer();
            RelativeDistinguishedName cnRdn = X509Util.getRdnFromName(issuer, AttributeTypeObjectIdentifiers.COMMON_NAME);
            addAttributeToCn(cnRdn);
        };
    }

    private static void addAttributeToCn(RelativeDistinguishedName cn) {
        AttributeTypeAndValue attributeTypeAndValue = new AttributeTypeAndValue("additional-cn", DirectoryStringChoiceType.PRINTABLE_STRING);

        Asn1ObjectIdentifier asn1ObjectIdentifier = new Asn1ObjectIdentifier("cn");
        asn1ObjectIdentifier.setValue(AttributeTypeObjectIdentifiers.COMMON_NAME);
        attributeTypeAndValue.setType(asn1ObjectIdentifier);

        Asn1OctetString asn1OctetString = new Asn1OctetString("additional-cn");
        asn1OctetString.setValue("additional-cn".getBytes());
        attributeTypeAndValue.setValue(asn1OctetString);

        cn.addAttributeTypeAndValue(attributeTypeAndValue);
    }
}
