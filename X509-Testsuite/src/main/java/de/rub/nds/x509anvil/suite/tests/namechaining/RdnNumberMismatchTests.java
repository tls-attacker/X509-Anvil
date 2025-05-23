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
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.X500AttributeType;

import java.util.ArrayList;
import java.util.List;

public class RdnNumberMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two distinguished names DN1 and DN2 match if they have the same number of RDNs")
    @SeverityLevel(Severity.CRITICAL)
    @AnvilTest(id = "")
    public void missingRdn(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            List<Pair<X500AttributeType, String>> subject = config.getSubject();
            List<Pair<X500AttributeType, String>> newSubject = new ArrayList<>();

            subject.forEach(pair -> {
                if (pair.getKey() != X500AttributeType.COUNTRY_NAME) {
                    newSubject.add(new Pair<>(pair.getKey(), pair.getValue()));
                }
            });
            config.setSubject(newSubject);
        });
    }

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two distinguished names DN1 and DN2 match if they have the same number of RDNs")
    @SeverityLevel(Severity.CRITICAL)
    @AnvilTest(id = "")
    public void additionalRdn(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            Pair<X500AttributeType, String> newPair = new Pair<>(X500AttributeType.DOMAIN_COMPONENT, "additional_rdn");
            List<Pair<X500AttributeType, String>> modifiableSubject = new ArrayList<>(config.getSubject());
            modifiableSubject.add(newPair);
            config.setSubject(modifiableSubject);
        });
    }
}
