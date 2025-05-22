package de.rub.nds.x509anvil.suite.tests.basicfields.validity;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import org.joda.time.DateTime;

public class ExpiredTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "6.1.3. Basic Certificate Processing", text = "The certificate validity period includes the current time.")
    @SeverityLevel(Severity.CRITICAL)
            @IpmLimitations(identifiers = "entity:not_after")
    @AnvilTest
    public void expiredUtcEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true,
                (X509CertificateConfigModifier) config -> {
                    config.setNotAfter(new DateTime(2020, 1, 1, 0, 0, 0));
                    config.setDefaultNotAfterEncoding(ValidityEncoding.UTC);
                });
    }

    @Specification(document = "RFC 5280", section = "6.1.3. Basic Certificate Processing", text = "The certificate validity period includes the current time.")
    @SeverityLevel(Severity.CRITICAL)
            @IpmLimitations(identifiers = "entity:not_after")
    @AnvilTest
    public void expiredGeneralizedEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true,
                (X509CertificateConfigModifier) config -> {
                    config.setNotAfter(new DateTime(2020, 1, 1, 0, 0, 0));
                    config.setDefaultNotAfterEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
                });
    }

    @Specification(document = "RFC 5280", section = "6.1.3. Basic Certificate Processing", text = "The certificate validity period includes the current time.")
    @SeverityLevel(Severity.CRITICAL)
            @IpmLimitations(identifiers = "inter0:not_after")
    @AnvilTest
    public void expiredUtcIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
                (X509CertificateConfigModifier) config -> {
                    config.setNotAfter(new DateTime(2001, 1, 1, 0, 0, 0));
                    config.setDefaultNotAfterEncoding(ValidityEncoding.UTC);
                });
    }


    @Specification(document = "RFC 5280", section = "6.1.3. Basic Certificate Processing", text = "The certificate validity period includes the current time.")
    @SeverityLevel(Severity.CRITICAL)
            @IpmLimitations(identifiers = "inter0:not_after")
    @AnvilTest
    public void expiredGeneralizedIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
                (X509CertificateConfigModifier) config -> {
                    config.setNotAfter(new DateTime(2020, 1, 1, 0, 0, 0));
                    config.setDefaultNotAfterEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
                });
    }
}
