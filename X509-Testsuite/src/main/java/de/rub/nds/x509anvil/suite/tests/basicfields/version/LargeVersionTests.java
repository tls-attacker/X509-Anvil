package de.rub.nds.x509anvil.suite.tests.basicfields.version;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

import java.math.BigInteger;

public class LargeVersionTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1", text = "Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }")
    @AnvilTest(id = "")
            @IpmLimitations(identifiers = "entity:version")
    public void largeVersionEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> config.setVersion(new BigInteger("256")));
    }

    @Specification(document = "RFC 5280", section = "4.1", text = "Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }")
    @AnvilTest(id = "")
            @IpmLimitations(identifiers = "inter0:version")
    public void largeVersionIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
                (X509CertificateConfigModifier) config -> config.setVersion(new BigInteger("256")));
    }
}
