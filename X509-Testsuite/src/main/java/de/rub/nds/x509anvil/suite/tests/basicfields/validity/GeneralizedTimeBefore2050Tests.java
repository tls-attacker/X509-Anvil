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

public class GeneralizedTimeBefore2050Tests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:not_before")
    @AnvilTest(id = "basic-3f9a198ac8")
    public void generalizedTimeBefore2050BeforeEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotBefore(new DateTime(2020, 1, 1, 0, 0));
                            config.setDefaultNotBeforeEncoding(
                                    ValidityEncoding.GENERALIZED_TIME_UTC);
                        });
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:not_before")
    @AnvilTest(id = "basic-3f2aca81b6")
    public void generalizedTimeBefore2050BeforeIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotBefore(new DateTime(2020, 1, 1, 0, 0));
                            config.setDefaultNotBeforeEncoding(
                                    ValidityEncoding.GENERALIZED_TIME_UTC);
                        });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:not_after")
    @AnvilTest(id = "basic-3f9b9cf188")
    public void generalizedTimeBefore2050AfterEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotAfter(new DateTime(2030, 1, 1, 0, 0));
                            config.setDefaultNotBeforeEncoding(
                                    ValidityEncoding.GENERALIZED_TIME_UTC);
                        });
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:not_after")
    @AnvilTest(id = "basic-1ef52d9ac8")
    public void generalizedTimeBefore2050AfterIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setNotAfter(new DateTime(2030, 1, 1, 0, 0));
                            config.setDefaultNotBeforeEncoding(
                                    ValidityEncoding.GENERALIZED_TIME_UTC);
                        });
    }
}
