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
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class AuthorityKeyIdentifierExtensionConfig extends ExtensionConfig {

    public AuthorityKeyIdentifierExtensionConfig() {
        super(ExtensionObjectIdentifiers.AUTHORITY_KEY_IDENTIFIER, "authorityKeyIdentifier");
    }

    @Override
    public Asn1OctetString getContentAsn1Structure(X509CertificateConfig certificateConfig,
                                                   X509CertificateConfig previousConfig) {
        byte[] derEncoded;
        try {
            JcaX509ExtensionUtils jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
            AuthorityKeyIdentifier authorityKeyIdentifier =
                jcaX509ExtensionUtils.createAuthorityKeyIdentifier(previousConfig.getPublicKeyJavaFormat());
            derEncoded = authorityKeyIdentifier.getEncoded();
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException("Unable to encode authority key identifier", e);
        }
        Asn1OctetString extensionValue = new Asn1OctetString("authorityKeyId");
        extensionValue.setValue(derEncoded);
        return extensionValue;
    }
}