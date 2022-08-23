package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.RFC;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
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

import java.util.Collections;
import java.util.List;

public class RdnOrderMismatchTests extends X509AnvilTest {

    @RFC(number = 5280, section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two distinguished names DN1 and DN2 match if [...] and the matching RDNs appear in the same order in both DNs")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void rdnOrderMismatch(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        // Add dnq just to make sure that there are at least 2 rdns
        chainConfig.getIntermediateConfig(0).getSubject().addNameComponent(AttributeTypeObjectIdentifiers.DN_QUALIFIER,
                "dnq", DirectoryStringType.PRINTABLE);
        VerifierResult result = testRunner.execute(chainConfig, reverseRdnsOrderModifier());
        Assertions.assertFalse(result.isValid());
    }

    private static X509CertificateModifier reverseRdnsOrderModifier() {
        return (certificate, config, previousConfig) -> {
            if (config.isEntity()) {
                Asn1Sequence subjectAsn1 = (Asn1Sequence) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "issuer");
                List<Asn1Encodable> shallowCopy = subjectAsn1.getChildren().subList(0, subjectAsn1.getChildren().size());
                Collections.reverse(shallowCopy);
                subjectAsn1.setChildren(shallowCopy);
            }
        };
    }
}
