package de.rub.nds.x509anvil.suite.tests.extensions.authoritykeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class OnlySerialNumberTest extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "A.2. Implicitly Tagged Module, 1988 Syntax",
            text = "authorityCertIssuer and authorityCertSerialNumber MUST both be present or both be absent")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_authority_key_identifier_present", method = "enabled")
    public void missingKeyIdentifierEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement with extension
//        assertInvalid(argumentsAccessor, testRunner, true, (X509CertificateConfigModifier) config -> {
//            // Placeholder for future extension implementation
//            serialWithoutIssuerModifier(true);
//        });
    }


    @Specification(document = "RFC 5280", section = "A.2. Implicitly Tagged Module, 1988 Syntax",
            text = "authorityCertIssuer and authorityCertSerialNumber MUST both be present or both be absent")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_subject_key_identifier_present", method = "enabled")
    public void missingKeyIdentifierIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement with extension
//        assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config -> {
//            // Placeholder for future extension implementation
//            serialWithoutIssuerModifier(true); // Assuming serialWithoutIssuerModifier will be implemented
//        });
    }



// TODO: re-implement with extension
        /*
         public static X509CertificateConfigModifier serialWithoutIssuerModifier(boolean entity) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Extension extension = X509Util.getExtensionByOid(certificate, ExtensionObjectIdentifiers.AUTHORITY_KEY_IDENTIFIER);
                Asn1OctetString extnValue = extension.getExtnValue();

                AuthorityKeyIdentifier authorityKeyIdentifierAsn1 = new AuthorityKeyIdentifier("withoutIssuer");
                Asn1OctetString keyIdentifierAsn1 = new Asn1OctetString("key");
                authorityKeyIdentifierAsn1.setKeyIdentifier(keyIdentifierAsn1);

                try {
                    JcaX509ExtensionUtils jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
                    // TODO: fix with implemented config
                    // org.bouncycastle.asn1.x509.AuthorityKeyIdentifier authorityKeyIdentifier = jcaX509ExtensionUtils.createAuthorityKeyIdentifier(previousConfig.getPublicKeyJavaFormat());
                    // keyIdentifierAsn1.setValue(authorityKeyIdentifier.getKeyIdentifier());
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }

                Asn1Integer serialAsn1 = new Asn1Integer("serial");
                serialAsn1.setValue(previousConfig.getSerialNumber());
                authorityKeyIdentifierAsn1.setAuthorityCertSerialNumber(serialAsn1);

                Asn1FieldSerializer serializer = new Asn1FieldSerializer(authorityKeyIdentifierAsn1);
                byte[] derEncoded = serializer.serialize();
                extnValue.setValue(derEncoded);

            }
        };
    }
         */
}
