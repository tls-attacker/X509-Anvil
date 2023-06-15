/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config.extension;

import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class AuthorityKeyIdentifierExtensionConfig extends ExtensionConfig {

    public AuthorityKeyIdentifierExtensionConfig() {
        super(ExtensionObjectIdentifiers.AUTHORITY_KEY_IDENTIFIER, "authorityKeyIdentifier");
    }

    @Override
    public Asn1PrimitiveOctetString getContentAsn1Structure(X509CertificateConfig certificateConfig,
        X509CertificateConfig previousConfig) {
        byte[] derEncoded;
        try {
            JcaX509ExtensionUtils jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
            AuthorityKeyIdentifier authorityKeyIdentifier =
                jcaX509ExtensionUtils.createAuthorityKeyIdentifier(previousConfig.getKeyPair().getPublic());
            derEncoded = authorityKeyIdentifier.getEncoded();
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException("Unable to encode authority key identifier", e);
        }
        Asn1PrimitiveOctetString extensionValue = new Asn1PrimitiveOctetString();
        extensionValue.setValue(derEncoded);
        return extensionValue;
    }
}