package de.rub.nds.x509anvil.suite.tests.extensions.issueralternativename;

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

public class IssuerAlternativeNameIssuerTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-8c049a0d2d" )
    public void issuerAltNameMailInIssuerEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {},
            (X509CertificateConfigModifier) config -> {
                LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
                subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "mail@test.com"));
                subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
                subject.add(new Pair<>(X500AttributeType.COUNTRY_NAME, "Global"));
                config.setSubject(subject);
            });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-ae73e0f75b" )
    public void issuerAltNameMailInIssuerIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {},
            (X509CertificateConfigModifier) config -> {
                LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
                subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "mail@test.com"));
                subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
                subject.add(new Pair<>(X500AttributeType.COUNTRY_NAME, "Global"));
                config.setSubject(subject);
            });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-0e2e4cd7b4" )
    public void issuerAltNameDomainNameInIssuerEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {},
            (X509CertificateConfigModifier) config -> {
                LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
                subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "test.com"));
                subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
                subject.add(new Pair<>(X500AttributeType.COUNTRY_NAME, "Global"));
                config.setSubject(subject);
            });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-5419ef48ce" )
    public void issuerAltNameDomainNameInIssuerIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {},
            (X509CertificateConfigModifier) config -> {
                LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
                subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "test.com"));
                subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
                subject.add(new Pair<>(X500AttributeType.COUNTRY_NAME, "Global"));
                config.setSubject(subject);
            });
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id  = "extension-4cb6303918" )
    public void issuerAltNameIpInIssuerEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {},
            (X509CertificateConfigModifier) config -> {
                LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
                subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "123.123.123.123"));
                subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
                subject.add(new Pair<>(X500AttributeType.COUNTRY_NAME, "Global"));
                config.setSubject(subject);
            });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id  = "extension-1619f2e27a" )
    public void issuerAltNameIpInIssuerIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {},
            (X509CertificateConfigModifier) config -> {
                LinkedList<Pair<X500AttributeType, String>> subject = new LinkedList<>();
                subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "123.123.123.123"));
                subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
                subject.add(new Pair<>(X500AttributeType.COUNTRY_NAME, "Global"));
                config.setSubject(subject);
            });
    }
}
