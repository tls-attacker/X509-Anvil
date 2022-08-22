package de.rub.nds.x509anvil.framework.x509.config.extension;

import de.rub.nds.asn1.encoder.Asn1EncoderForX509;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;
import de.rub.nds.x509attacker.linker.Linker;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

public class SubjectKeyIdentifierExtensionConfig extends ExtensionConfig {

    public SubjectKeyIdentifierExtensionConfig() {
        super(ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER, "subjectKeyIdentifier");
    }


    @Override
    public Asn1PrimitiveOctetString getContentAsn1Structure(X509CertificateConfig certificateConfig, X509CertificateConfig previousConfig) {
        Asn1PrimitiveOctetString subjectKeyIdentifierAsn1 = new Asn1PrimitiveOctetString();
        subjectKeyIdentifierAsn1.setIdentifier("subjectKeyIdentifier");
        try {
            JcaX509ExtensionUtils jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
            SubjectKeyIdentifier subjectKeyIdentifier = jcaX509ExtensionUtils.createSubjectKeyIdentifier(certificateConfig.getKeyPair().getPublic());
            subjectKeyIdentifierAsn1.setValue(subjectKeyIdentifier.getKeyIdentifier());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        byte[] derEncoded = Asn1EncoderForX509.encode(new Linker(new HashMap<>()), subjectKeyIdentifierAsn1);

        Asn1PrimitiveOctetString extensionValue = new Asn1PrimitiveOctetString();
        extensionValue.setValue(derEncoded);
        return extensionValue;
    }
}