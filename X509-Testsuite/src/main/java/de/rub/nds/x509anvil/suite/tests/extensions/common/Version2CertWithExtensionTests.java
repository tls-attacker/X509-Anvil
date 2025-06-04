package de.rub.nds.x509anvil.suite.tests.extensions.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

import java.math.BigInteger;

public class Version2CertWithExtensionTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present, entity:version")
    @AnvilTest(id = "extension-0a5be219fe")
    public void version2CertWithExtensionsEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            config.setVersion(BigInteger.valueOf(1));
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:version")
    @AnvilTest(id = "extension-2b30514cc9")
    public void version2CertWithExtensionsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            config.setVersion(BigInteger.valueOf(1));
            config.setIncludeExtensions(true);
        });
    }
}
