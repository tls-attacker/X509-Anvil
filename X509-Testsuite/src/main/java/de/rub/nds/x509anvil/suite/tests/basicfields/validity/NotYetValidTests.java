package de.rub.nds.x509anvil.suite.tests.basicfields.validity;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import org.joda.time.DateTime;

public class NotYetValidTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:not_before")
    @AnvilTest(id = "basic-0b35348dd5")
    public void notYetValidUtcEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true,
                (X509CertificateConfigModifier) config -> {
                    config.setNotBefore(new DateTime(2040, 1, 1, 0, 0, 0));
                    config.setDefaultNotBeforeEncoding(ValidityEncoding.UTC);
                });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:not_before")
    @AnvilTest(id = "basic-d0325d7e05")
    public void notYetValidGeneralizedEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true,
                (X509CertificateConfigModifier) config -> {
                    config.setNotBefore(new DateTime(2040, 1, 1, 0, 0, 0));
                    config.setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
                });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "inter0:not_before")
    @AnvilTest(id = "basic-48f16a250d")
    public void notYetValidUtcIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
                (X509CertificateConfigModifier) config -> {
                    config.setNotBefore(new DateTime(2040, 1, 1, 0, 0, 0));
                    config.setDefaultNotBeforeEncoding(ValidityEncoding.UTC);
                });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "inter0:not_before")
    @AnvilTest(id = "basic-5341312baf")
    public void notYetValidGeneralizedIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
                (X509CertificateConfigModifier) config -> {
                    config.setNotBefore(new DateTime(2040, 1, 1, 0, 0, 0));
                    config.setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC);
                });
    }

}
