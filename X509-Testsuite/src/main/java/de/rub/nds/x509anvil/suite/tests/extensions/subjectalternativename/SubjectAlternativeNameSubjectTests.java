package de.rub.nds.x509anvil.suite.tests.extensions.subjectalternativename;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.X500AttributeType;

import java.util.LinkedList;

public class SubjectAlternativeNameSubjectTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-9af0478bd0" )
    public void subjectAltNameMailInSubjectEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
            subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "mail@tls-attacker.com"));
            subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
            config.setSubject(subject);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-aad8a2245b" )
    public void subjectAltNameMailInSubjectIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
            subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "mail@tls-attacker.com"));
            subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
            config.setSubject(subject);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-402322d3de" )
    public void subjectAltNameDomainNameInSubjectEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
            subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "tls-attacker.com"));
            subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
            config.setSubject(subject);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-2dcf039fe2" )
    public void subjectAltNameDomainNameInSubjectIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
            subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "tls-attacker.com"));
            subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
            config.setSubject(subject);
        });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-4d10f6a130" )
    public void subjectAltNameIpInSubjectEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
            subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "123.123.123.123"));
            subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
            config.setSubject(subject);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-bbd5958633" )
    public void subjectAltNameIpInSubjectIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
            subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "123.123.123.123"));
            subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
            config.setSubject(subject);
        });
    }
}
