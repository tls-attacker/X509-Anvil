/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config.extension;

import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.security.NoSuchAlgorithmException;

public class SubjectKeyIdentifierExtensionConfig extends ExtensionConfig {

    public SubjectKeyIdentifierExtensionConfig() {
        super(ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER, "subjectKeyIdentifier");
    }

    @Override
    public Asn1OctetString getContentAsn1Structure(X509CertificateConfig certificateConfig,
                                                   X509CertificateConfig previousConfig) {
        Asn1OctetString subjectKeyIdentifierAsn1 = new Asn1OctetString("subjectKeyIdentifierAsn1");
        subjectKeyIdentifierAsn1.setIdentifier("subjectKeyIdentifier");
        try {
            JcaX509ExtensionUtils jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
            SubjectKeyIdentifier subjectKeyIdentifier =
                jcaX509ExtensionUtils.createSubjectKeyIdentifier(certificateConfig.getPublicKeyJavaFormat());
            subjectKeyIdentifierAsn1.setValue(subjectKeyIdentifier.getKeyIdentifier());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        Asn1FieldSerializer serializer = new Asn1FieldSerializer(subjectKeyIdentifierAsn1);
        byte[] derEncoded = serializer.serialize();

        Asn1OctetString extensionValue = new Asn1OctetString("subjectKeyIdentifier");
        extensionValue.setValue(derEncoded);
        return extensionValue;
    }
}
