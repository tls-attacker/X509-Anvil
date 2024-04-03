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
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.util.Collections;
import java.util.List;

public class RdnOrderMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two distinguished names DN1 and DN2 match if [...] and the matching RDNs appear in the same order in both DNs")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void rdnOrderMismatch(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        // Add dnq just to make sure that there are at least 2 rdns
        RelativeDistinguishedName rdn = new RelativeDistinguishedName("rdn");
        rdn.addAttributeTypeAndValue(new AttributeTypeAndValue("dnq", X500AttributeType.DN_QUALIFIER, "dnq"));
        chainConfig.getIntermediateConfig(0).getSubject().addRelativeDistinguishedNames(rdn);
        VerifierResult result = testRunner.execute(chainConfig, reverseRdnsOrderModifier());
        Assertions.assertFalse(result.isValid());
    }

    private static X509CertificateModifier reverseRdnsOrderModifier() {
        return (certificate, config, previousConfig) -> {
            if (config.isEntity()) {
                Name issuer = certificate.getTbsCertificate().getIssuer();
                List<RelativeDistinguishedName> shallowCopy = issuer.getRelativeDistinguishedNames().subList(0, issuer.getRelativeDistinguishedNames().size());
                Collections.reverse(shallowCopy);
                issuer.setRelativeDistinguishedNames(shallowCopy);
            }
        };
    }
}
