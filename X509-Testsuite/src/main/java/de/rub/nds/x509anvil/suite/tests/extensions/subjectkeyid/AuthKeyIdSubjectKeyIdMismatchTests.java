package de.rub.nds.x509anvil.suite.tests.extensions.subjectkeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.model.extensions.AuthorityKeyIdentifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class AuthKeyIdSubjectKeyIdMismatchTests extends X509AnvilTest {
    @Specification(document = "RFC 5280", section = "4.2.1.2. Subject Key Identifier",
            text = "In conforming CA certificates, the value of the subject key identifier MUST be the value placed in the key identifier " +
                    "field of the authority key identifier extension (Section 4.2.1.1) of certificates issued by the subject of this certificate.")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_subject_key_identifier_present", method = "enabled")
    @ValueConstraint(identifier = "entity.ext_authority_key_identifier_present", method = "enabled")
    public void keyIdMismatchEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, authKeyMismatch(true));
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.2.1.2. Subject Key Identifier",
            text = "In conforming CA certificates, the value of the subject key identifier MUST be the value placed in the key identifier " +
                    "field of the authority key identifier extension (Section 4.2.1.1) of certificates issued by the subject of this certificate.")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_authority_key_identifier_present", method = "enabled")
    public void keyIdMismatchIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, authKeyMismatch(false));
        Assertions.assertFalse(result.isValid());
    }

    public static X509CertificateModifier authKeyMismatch(boolean entity) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Extension extension = X509Util.getExtensionByOid(certificate, ExtensionObjectIdentifiers.AUTHORITY_KEY_IDENTIFIER);
                Asn1OctetString extnValue = extension.getExtnValue();

                AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier("auth_key");
                Asn1OctetString keyIdentifier = new Asn1OctetString("key");
                keyIdentifier.setValue(TestUtils.createByteArray(20));
                authorityKeyIdentifier.setKeyIdentifier(keyIdentifier);
                Asn1FieldSerializer serializer = new Asn1FieldSerializer(authorityKeyIdentifier);
                byte[] derEncoded = serializer.serialize();
                extnValue.setValue(derEncoded);

            }
        };
    }
}
