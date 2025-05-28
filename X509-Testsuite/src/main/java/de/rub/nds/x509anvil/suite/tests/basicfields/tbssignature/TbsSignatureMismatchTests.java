package de.rub.nds.x509anvil.suite.tests.basicfields.tbssignature;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;

public class TbsSignatureMismatchTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:key_type")
    @AnvilTest(id = "basic-3e2fbb009f")
    public void tbsSignatureDoesntMatchAlgorithmEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            config.amendSignatureAlgorithm(
                    TestUtils.getNonMatchingAlgorithmOid(
                            config.getDefaultSignatureAlgorithm()).getSignatureAlgorithm());
        });
    }

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "inter0:key_type")
    @AnvilTest(id = "basic-eec58410b3")
    public void tbsSignatureDoesntMatchAlgorithmIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            config.amendSignatureAlgorithm(
                    TestUtils.getNonMatchingAlgorithmOid(
                            config.getDefaultSignatureAlgorithm()).getSignatureAlgorithm());
        });
    }
}
