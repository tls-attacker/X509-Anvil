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

public class DomainComponentCaseInsensitiveTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "namechaining-85e5f0f10d")
    public void switchedCaseDomainComponentTest(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(testRunner, false, (X509CertificateConfigModifier) config -> {
            Pair<X500AttributeType, String> newPair = new Pair<>(X500AttributeType.DOMAIN_COMPONENT, "CaSeInSeNsItIvE");
            List<Pair<X500AttributeType, String>> modifiableSubject = new ArrayList<>(config.getSubject());
            modifiableSubject.add(newPair);
            config.setSubject(modifiableSubject);
            config.setSubjectDomainComponentCaseInsensitive(true);
        });
    }
}
