package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.asn1.model.Asn1PrimitiveIa5String;
import de.rub.nds.asn1.model.Asn1Sequence;
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
import de.rub.nds.x509anvil.suite.tests.util.Constraints;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class DomainComponentCaseInsensitiveTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.3. Internationalized Domain Names in Distinguished Names",
            text = "Conforming implementations shall perform a case-insensitive exact match when comparing domainComponent " +
                    "attributes in distinguished names")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.domain_components_present", method = "enabled")
    @AnvilTest()
    public void switchedCaseDomainComponentTest(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, domainComponentCaseSwitchModifier());
        Assertions.assertTrue(result.isValid());
    }

    private static X509CertificateModifier domainComponentCaseSwitchModifier() {
        return (certificate, config, previousConfig) -> {
            if (config.isEntity()) {
                Asn1Sequence subjectAsn1 = (Asn1Sequence) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "issuer");
                Asn1Sequence attribute = X509Util.getAttributeFromName(subjectAsn1, AttributeTypeObjectIdentifiers.DOMAIN_COMPONENT);
                if (attribute.getChildren().get(1) instanceof Asn1PrimitiveIa5String) {
                    Asn1PrimitiveIa5String value = (Asn1PrimitiveIa5String) attribute.getChildren().get(1);
                    value.setValue(value.getValue().toUpperCase());
                }
                else {
                    throw new RuntimeException("Could not change domain component");
                }
            }
        };
    }
}
