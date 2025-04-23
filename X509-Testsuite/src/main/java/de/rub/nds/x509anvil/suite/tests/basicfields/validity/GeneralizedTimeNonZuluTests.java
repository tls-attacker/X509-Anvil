package de.rub.nds.x509anvil.suite.tests.basicfields.validity;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public class GeneralizedTimeNonZuluTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.2.5.2. GeneralizedTime",
            text = "For the purposes of this profile, GeneralizedTime values MUST be expressed in Greenwich Mean Time (Zulu)")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "entity:not_before")
    @AnvilTest
    public void notBeforeEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        //TODO: Zulu time needs to be prepared based on config (Z still present)
        assertInvalid(testRunner, true,
                (X509CertificateConfigModifier) config -> {
                    config.setNotBefore(new DateTime(2020, 1, 1, 0, 0, 0, DateTimeZone.forOffsetHours(1)));
                    config.setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
                });
    }


    @Specification(document = "RFC 5280", section = "4.1.2.5.2. GeneralizedTime",
            text = "For the purposes of this profile, GeneralizedTime values MUST be expressed in Greenwich Mean Time (Zulu)")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "inter0:not_before")
    @AnvilTest
    public void notBeforeIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        //TODO: Zulu time needs to be prepared based on config (Z still present)
        assertInvalid(testRunner, false,
                (X509CertificateConfigModifier) config -> {
                    config.setNotBefore(new DateTime(2020, 1, 1, 0, 0, 0, DateTimeZone.forOffsetHours(1)));
                    config.setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
                });
    }


    @Specification(document = "RFC 5280", section = "4.1.2.5.2. GeneralizedTime",
            text = "For the purposes of this profile, GeneralizedTime values MUST be expressed in Greenwich Mean Time (Zulu)")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "entity:not_after")
    @AnvilTest
    public void notAfterEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        //TODO: Zulu time needs to be prepared based on config (Z still present)
        assertInvalid(testRunner, true,
                (X509CertificateConfigModifier) config -> {
                    config.setNotAfter(new DateTime(2050, 1, 1, 0, 0, 0, DateTimeZone.forOffsetHours(1)));
                    config.setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
                });
    }



    @Specification(document = "RFC 5280", section = "4.1.2.5.2. GeneralizedTime",
            text = "For the purposes of this profile, GeneralizedTime values MUST be expressed in Greenwich Mean Time (Zulu)")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @IpmLimitations(identifiers = "inter0:not_after")
    @AnvilTest
    public void notAfterIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        //TODO: Zulu time needs to be prepared based on config (Z still present)
        assertInvalid(testRunner, false,
                (X509CertificateConfigModifier) config -> {
                    config.setNotAfter(new DateTime(2050, 1, 1, 0, 0, 0, DateTimeZone.forOffsetHours(1)));
                    config.setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
                });
    }

}
