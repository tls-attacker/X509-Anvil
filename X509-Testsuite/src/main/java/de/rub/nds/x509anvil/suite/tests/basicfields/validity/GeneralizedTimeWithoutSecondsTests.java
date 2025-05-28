package de.rub.nds.x509anvil.suite.tests.basicfields.validity;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.asn1.constants.TimeAccurracy;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import org.joda.time.DateTime;

public class GeneralizedTimeWithoutSecondsTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:not_before")
    @AnvilTest(id = "basic-b09833f225")
    public void notBeforeEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true,
                (X509CertificateConfigModifier) config -> {
                    config.setNotBefore(new DateTime(2000, 1, 1, 0, 0, 0));
                    config.setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
                    config.setNotBeforeAccurracy(TimeAccurracy.MINUTES);
                });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "inter0:not_before")
    @AnvilTest(id = "basic-b1e7273312")
    public void notBeforeIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
                (X509CertificateConfigModifier) config -> {
                    config.setNotBefore(new DateTime(2000, 1, 1, 0, 0, 0));
                    config.setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
                    config.setNotBeforeAccurracy(TimeAccurracy.MINUTES);
                });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:not_after")
    @AnvilTest(id = "basic-0a0797aef4")
    public void notAfterEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true,
                (X509CertificateConfigModifier) config -> {
                    config.setNotAfter(new DateTime(2050, 1, 1, 0, 0, 0));
                    config.setDefaultNotAfterEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
                    config.setNotAfterAccurracy(TimeAccurracy.MINUTES);
                });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "inter0:not_after")
    @AnvilTest(id = "basic-beb1b04e7a")
    public void notAfterIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
                (X509CertificateConfigModifier) config -> {
                    config.setNotAfter(new DateTime(2050, 1, 1, 0, 0, 0));
                    config.setDefaultNotAfterEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
                    config.setNotAfterAccurracy(TimeAccurracy.MINUTES);
                });
    }
}
