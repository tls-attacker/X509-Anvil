package de.rub.nds.x509anvil.suite.tests.extensions.authoritykeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.asn1.encoder.Asn1EncoderForX509;
import de.rub.nds.asn1.model.Asn1Implicit;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.RFC;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
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
import de.rub.nds.x509anvil.suite.tests.util.Constraints;
import de.rub.nds.x509attacker.linker.Linker;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

public class OnlySerialNumberTest extends X509AnvilTest {

    @RFC(number = 5280, section = "A.2. Implicitly Tagged Module, 1988 Syntax",
            text = "authorityCertIssuer and authorityCertSerialNumber MUST both be present or both be absent")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_subject_key_identifier_present", clazz = Constraints.class, method = "enabled")
    @ValueConstraint(identifier = "entity.ext_authority_key_identifier_present", clazz = Constraints.class, method = "enabled")
    public void missingKeyIdentifierEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, serialWithoutIssuerModifier(true));
        Assertions.assertFalse(result.isValid());
    }


    public static X509CertificateModifier serialWithoutIssuerModifier(boolean entity) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1Sequence extension = X509Util.getExtensionByOid(certificate, ExtensionObjectIdentifiers.AUTHORITY_KEY_IDENTIFIER);
                Asn1PrimitiveOctetString extnValue;
                if (extension.getChildren().get(1) instanceof Asn1PrimitiveOctetString) {
                    extnValue = (Asn1PrimitiveOctetString) extension.getChildren().get(1);
                }
                else if (extension.getChildren().get(2) instanceof Asn1PrimitiveOctetString) {
                    extnValue = (Asn1PrimitiveOctetString) extension.getChildren().get(2);
                }
                else {
                    throw new RuntimeException("Extension has no value");
                }

                Asn1Sequence authorityKeyIdentifierAsn1 = new Asn1Sequence();

                Asn1Implicit keyIdImplicit = new Asn1Implicit();
                keyIdImplicit.setOffset(0);
                Asn1PrimitiveOctetString keyIdentifierAsn1 = new Asn1PrimitiveOctetString();
                keyIdImplicit.addChild(keyIdentifierAsn1);
                authorityKeyIdentifierAsn1.addChild(keyIdImplicit);

                try {
                    JcaX509ExtensionUtils jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
                    AuthorityKeyIdentifier authorityKeyIdentifier = jcaX509ExtensionUtils.createAuthorityKeyIdentifier(previousConfig.getKeyPair().getPublic());
                    keyIdentifierAsn1.setValue(authorityKeyIdentifier.getKeyIdentifier());
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }

                Asn1Implicit serialImplicit = new Asn1Implicit();
                serialImplicit.setOffset(2);
                Asn1Integer serialAsn1 = new Asn1Integer();
                serialImplicit.addChild(serialAsn1);
                serialAsn1.setValue(previousConfig.getSerialNumber());
                authorityKeyIdentifierAsn1.addChild(serialImplicit);


                byte[] derEncoded = Asn1EncoderForX509.encode(new Linker(new HashMap<>()), authorityKeyIdentifierAsn1);
                extnValue.setValue(derEncoded);

            }
        };
    }
}
