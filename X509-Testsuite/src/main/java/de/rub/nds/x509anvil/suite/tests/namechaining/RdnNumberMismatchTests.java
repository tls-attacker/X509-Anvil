package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.X500AttributeType;

import java.util.ArrayList;
import java.util.List;

public class RdnNumberMismatchTests extends X509AnvilTest {

    @ChainLength(minLength = 3)
    @AnvilTest(id = "namechaining-f284c832ec")
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

    @ChainLength(minLength = 3)
    @AnvilTest(id = "namechaining-b1401df33c")
    public void additionalRdn(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            Pair<X500AttributeType, String> newPair = new Pair<>(X500AttributeType.DOMAIN_COMPONENT, "additional_rdn");
            List<Pair<X500AttributeType, String>> modifiableSubject = new ArrayList<>(config.getSubject());
            modifiableSubject.add(newPair);
            config.setSubject(modifiableSubject);
        });
    }
}
