package de.rub.nds.x509anvil.suite.tests.extensions.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
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
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class V3CertWithUniqueIdsButNoExtnsTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest

    public void v3WithoutExtensionsWithSubjectUIdEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
// TODO: re-implement when extension implemented in attacker
        /*  assertInvalid(argumentsAccessor, testRunner, true, (X509CertificateConfigModifier) config -> {
            config.setVersion(3);
            config.setExtensionsPresent(false);
            config.setSubjectUniqueIdPresent(true);
            config.setSubjectUniqueId(new BitString(new byte[]{0, 1, 2, 3}));
        });*/
    }


    @Specification(document = "RFC 5280", section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest

//TODO: re-implement when extension implemented in attacker
    public void v3WithoutExtensionsWithSubjectUIdIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {

/*        assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config -> {
            config.setVersion(3);
            config.setExtensionsPresent(false);
            config.setSubjectUniqueIdPresent(true);
            config.setSubjectUniqueId(new BitString(new byte[]{0, 1, 2, 3}));
        });
        */
    }


    @Specification(document = "RFC 5280", section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void v3WithoutExtensionsWithIssuerUIdEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//        TODO: re-implement when extension implemented in attacker
/*        assertInvalid(argumentsAccessor, testRunner, true, (X509CertificateConfigModifier) config -> {
            config.setVersion(3);
            config.setExtensionsPresent(false);
            config.setIssuerUniqueIdPresent(true);
            config.setIssuerUniqueId(new BitString(new byte[]{0, 1, 2, 3}));
        });*/
    }


    @Specification(document = "RFC 5280", section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void v3WithoutExtensionsWithIssuerUIdIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
// TODO: re-implement when extension implemented in attacker
 /*         assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config -> {
            config.setVersion(3);
            config.setExtensionsPresent(false);
            config.setIssuerUniqueIdPresent(true);
            config.setIssuerUniqueId(new BitString(new byte[]{0, 1, 2, 3}));
        });*/
    }

}
