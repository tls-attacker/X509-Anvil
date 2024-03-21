/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config.extension;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;

import java.util.HashMap;

public class UnknownExtensionConfig extends ExtensionConfig {

    public UnknownExtensionConfig() {
        super(ExtensionObjectIdentifiers.UNKNOWN_EXTENSION, "unknownExtension");
    }

    @Override
    protected Asn1PrimitiveOctetString getContentAsn1Structure(X509CertificateConfig certificateConfig,
        X509CertificateConfig previousConfig) throws CertificateGeneratorException {
        Asn1PrimitiveBitString unknownExtAsn1 = new Asn1PrimitiveBitString();
        unknownExtAsn1.setIdentifier("unknownExtension");
        unknownExtAsn1.setValue(new byte[] { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70 });

        byte[] derEncoded = Asn1EncoderForX509.encode(new Linker(new HashMap<>()), unknownExtAsn1);
        Asn1PrimitiveOctetString extensionValue = new Asn1PrimitiveOctetString();
        extensionValue.setValue(derEncoded);
        return extensionValue;
    }
}
