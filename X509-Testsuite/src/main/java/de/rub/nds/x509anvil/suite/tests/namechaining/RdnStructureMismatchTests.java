package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.config.model.DirectoryStringType;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.platform.commons.JUnitException;

public class RdnStructureMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest(description = "Test if certificates are rejected where all attributes are encoded in a single RDN")
    public void rdnStructureMismatch(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).getSubject().addNameComponent(AttributeTypeObjectIdentifiers.DN_QUALIFIER, "dnq", DirectoryStringType.PRINTABLE);
        VerifierResult result = testRunner.execute(chainConfig, mergeRdnsModifier());
        Assertions.assertFalse(result.isValid());
    }

    private static X509CertificateModifier mergeRdnsModifier() {
        return (certificate, config, previousConfig) -> {
            if (config.isEntity()) {
                Asn1Sequence subjectAsn1 = (Asn1Sequence) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "issuer");
                if (subjectAsn1.getChildren().size() <= 1) {
                    throw new JUnitException("At least 2 name components required");
                }
                Asn1Set firstRnd = (Asn1Set) subjectAsn1.getChildren().get(0);
                int ataaIdentifier = 1;
                for (int i = 1; i < subjectAsn1.getChildren().size(); i++) {
                    Asn1Set rdn = (Asn1Set) subjectAsn1.getChildren().get(i);
                    for (Asn1Encodable asn1Encodable : rdn.getChildren()) {
                        asn1Encodable.setIdentifier("attributeTypeAndValue" + ataaIdentifier++);
                        firstRnd.addChild(asn1Encodable);
                    }
                }
                subjectAsn1.getChildren().subList(1, subjectAsn1.getChildren().size()).clear();
            }
        };
    }
}
