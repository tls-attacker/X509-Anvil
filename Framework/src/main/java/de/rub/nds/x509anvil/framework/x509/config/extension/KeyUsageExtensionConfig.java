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
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;

public class KeyUsageExtensionConfig extends ExtensionConfig {
    public static int DIGITAL_SIGNATURE = 128;
    public static int NON_REPUDIATION = 64;
    public static int KEY_ENCIPHERMENT = 32;
    public static int DATA_ENCIPHERMENT = 16;
    public static int KEY_AGREEMENT = 8;
    public static int KEY_CERT_SIGN = 4;
    public static int CRL_SIGN = 2;
    public static int ENCIPHER_ONLY = 1;
    public static int DECIPHER_ONLY = 128 << 8;

    private final byte[] flags = new byte[2];

    public KeyUsageExtensionConfig() {
        super(ExtensionObjectIdentifiers.KEY_USAGE, "keyUsage");
    }

    public boolean isFlagSet(int flag) {
        if (flag <= 128) {
            return (flags[0] & flag) == flag;
        } else {
            return (flags[1] & (flag >> 8)) == flag >> 8;
        }
    }

    public void setFlag(int flag, boolean value) {
        if (flag <= 128) {
            if (value) {
                flags[0] |= flag;
            } else {
                flags[0] &= ~flag;
            }
        } else {
            if (value) {
                flags[1] |= flag >> 8;
            } else {
                flags[1] &= ~(flag >> 8);
            }
        }
    }

    public boolean isDigitalSignature() {
        return (flags[0] & DIGITAL_SIGNATURE) == DIGITAL_SIGNATURE;
    }

    public void setDigitalSignature(boolean digitalSignature) {
        if (digitalSignature) {
            flags[0] |= DIGITAL_SIGNATURE;
        } else {
            flags[0] &= ~DIGITAL_SIGNATURE;
        }
    }

    public boolean isNonRepudiation() {
        return (flags[0] & NON_REPUDIATION) == NON_REPUDIATION;
    }

    public void setNonRepudiation(boolean nonRepudiation) {
        if (nonRepudiation) {
            flags[0] |= NON_REPUDIATION;
        } else {
            flags[0] &= ~NON_REPUDIATION;
        }
    }

    public boolean isKeyEncipherment() {
        return (flags[0] & KEY_ENCIPHERMENT) == KEY_ENCIPHERMENT;
    }

    public void setKeyEncipherment(boolean keyEncipherment) {
        if (keyEncipherment) {
            flags[0] |= KEY_ENCIPHERMENT;
        } else {
            flags[0] &= ~KEY_ENCIPHERMENT;
        }
    }

    public boolean isDataEncipherment() {
        return (flags[0] & DATA_ENCIPHERMENT) == DATA_ENCIPHERMENT;
    }

    public void setDataEncipherment(boolean dataEncipherment) {
        if (dataEncipherment) {
            flags[0] |= DATA_ENCIPHERMENT;
        } else {
            flags[0] &= ~DATA_ENCIPHERMENT;
        }
    }

    public boolean isKeyAgreement() {
        return (flags[0] & KEY_AGREEMENT) == KEY_AGREEMENT;
    }

    public void setKeyAgreement(boolean keyAgreement) {
        if (keyAgreement) {
            flags[0] |= KEY_AGREEMENT;
        } else {
            flags[0] &= ~KEY_AGREEMENT;
        }
    }

    public boolean isKeyCertSign() {
        return (flags[0] & KEY_CERT_SIGN) == KEY_CERT_SIGN;
    }

    public void setKeyCertSign(boolean keyCertSign) {
        if (keyCertSign) {
            flags[0] |= KEY_CERT_SIGN;
        } else {
            flags[0] &= ~KEY_CERT_SIGN;
        }
    }

    public boolean iscRLSign() {
        return (flags[0] & CRL_SIGN) == CRL_SIGN;
    }

    public void setcRLSign(boolean cRLSign) {
        if (cRLSign) {
            flags[0] |= CRL_SIGN;
        } else {
            flags[0] &= ~CRL_SIGN;
        }
    }

    public boolean isEncipherOnly() {
        return (flags[0] & ENCIPHER_ONLY) == ENCIPHER_ONLY;
    }

    public void setEncipherOnly(boolean encipherOnly) {
        if (encipherOnly) {
            flags[0] |= ENCIPHER_ONLY;
        } else {
            flags[0] &= ~ENCIPHER_ONLY;
        }
    }

    public boolean isDecipherOnly() {
        return (flags[1] & (DECIPHER_ONLY >> 8)) == (DECIPHER_ONLY >> 8);
    }

    public void setDecipherOnly(boolean decipherOnly) {
        if (decipherOnly) {
            flags[1] |= (DECIPHER_ONLY >> 8);
        } else {
            flags[1] &= ~(DECIPHER_ONLY >> 8);
        }
    }

    public void unsetAllBits() {
        flags[0] = 0;
        flags[1] = 0;
    }

    public byte[] getFlags() {
        return flags;
    }

    @Override
    protected Asn1PrimitiveOctetString getContentAsn1Structure(X509CertificateConfig certificateConfig,
        X509CertificateConfig previousConfig) {
        Asn1PrimitiveBitString keyUsageAsn1 = new Asn1PrimitiveBitString();
        keyUsageAsn1.setIdentifier("keyUsage");
        keyUsageAsn1.setValue(flags);
        keyUsageAsn1.setUnusedBits(7);

        Asn1FieldSerializer serializer = new Asn1FieldSerializer(keyUsageAsn1);
        byte[] derEncoded = serializer.serialize();
        Asn1PrimitiveOctetString extensionValue = new Asn1PrimitiveOctetString();
        extensionValue.setValue(derEncoded);
        return extensionValue;
    }
}
