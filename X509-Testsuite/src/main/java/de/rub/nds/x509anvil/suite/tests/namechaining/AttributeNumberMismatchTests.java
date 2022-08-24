package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.Asn1Set;
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
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
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
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, missingAttributeModifier());
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two relative distinguished names RDN1 and RDN2 match if they have the same number of naming attributes")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void additionalAttribute(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, additionalAttributeModifier());
        Assertions.assertFalse(result.isValid());
    }

    // Ads an additional "distinguished name qualifier" to the intermediate's subject
    private static X509CertificateModifier missingAttributeModifier() {
        return (certificate, config, previousConfig) -> {
            if (config.isIntermediate()) {
                Asn1Sequence subjectAsn1 = (Asn1Sequence) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "subject");
                Asn1Set cnRdn = X509Util.getRdnFromName(subjectAsn1, AttributeTypeObjectIdentifiers.COMMON_NAME);
                addAttributeToCn(cnRdn);
            }
        };
    }

    // Ads an additional "distinguished name qualifier" to the entity's issuer
    private static X509CertificateModifier additionalAttributeModifier() {
        return (certificate, config, previousConfig) -> {
            if (config.isEntity()) {
                Asn1Sequence issuerAsn1 = (Asn1Sequence) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "issuer");
                Asn1Set cnRdn = X509Util.getRdnFromName(issuerAsn1, AttributeTypeObjectIdentifiers.COMMON_NAME);
                addAttributeToCn(cnRdn);
            }
        };
    }

    private static void addAttributeToCn(Asn1Set cn) {
        Asn1Sequence cnAttribute = new Asn1Sequence();
        Asn1ObjectIdentifier type = new Asn1ObjectIdentifier();
        type.setValue(AttributeTypeObjectIdentifiers.COMMON_NAME);
        cnAttribute.addChild(type);
        Asn1PrimitivePrintableString value = new Asn1PrimitivePrintableString();
        value.setValue("additional-cn");
        cnAttribute.addChild(value);
        cn.addChild(cnAttribute);
    }
}
