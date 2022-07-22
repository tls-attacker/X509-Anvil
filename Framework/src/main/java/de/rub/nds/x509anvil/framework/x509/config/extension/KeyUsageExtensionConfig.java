package de.rub.nds.x509anvil.framework.x509.config.extension;

import de.rub.nds.asn1.encoder.Asn1EncoderForX509;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509attacker.linker.Linker;

import java.util.HashMap;

public class KeyUsageExtensionConfig extends ExtensionConfig {
    private boolean digitalSignature = false;
    private boolean nonRepudiation = false;
    private boolean keyEncipherment = false;
    private boolean dataEncipherment = false;
    private boolean keyAgreement = false;
    private boolean keyCertSign = true;
    private boolean cRLSign = false;
    private boolean encipherOnly = false;
    private boolean decipherOnly = false;

    public KeyUsageExtensionConfig() {
        super(ExtensionObjectIdentifiers.KEY_USAGE, "keyUsage");
    }

    public boolean isDigitalSignature() {
        return digitalSignature;
    }

    public void setDigitalSignature(boolean digitalSignature) {
        this.digitalSignature = digitalSignature;
    }

    public boolean isNonRepudiation() {
        return nonRepudiation;
    }

    public void setNonRepudiation(boolean nonRepudiation) {
        this.nonRepudiation = nonRepudiation;
    }

    public boolean isKeyEncipherment() {
        return keyEncipherment;
    }

    public void setKeyEncipherment(boolean keyEncipherment) {
        this.keyEncipherment = keyEncipherment;
    }

    public boolean isDataEncipherment() {
        return dataEncipherment;
    }

    public void setDataEncipherment(boolean dataEncipherment) {
        this.dataEncipherment = dataEncipherment;
    }

    public boolean isKeyAgreement() {
        return keyAgreement;
    }

    public void setKeyAgreement(boolean keyAgreement) {
        this.keyAgreement = keyAgreement;
    }

    public boolean isKeyCertSign() {
        return keyCertSign;
    }

    public void setKeyCertSign(boolean keyCertSign) {
        this.keyCertSign = keyCertSign;
    }

    public boolean iscRLSign() {
        return cRLSign;
    }

    public void setcRLSign(boolean cRLSign) {
        this.cRLSign = cRLSign;
    }

    public boolean isEncipherOnly() {
        return encipherOnly;
    }

    public void setEncipherOnly(boolean encipherOnly) {
        this.encipherOnly = encipherOnly;
    }

    public boolean isDecipherOnly() {
        return decipherOnly;
    }

    public void setDecipherOnly(boolean decipherOnly) {
        this.decipherOnly = decipherOnly;
    }

    @Override
    protected Asn1PrimitiveOctetString getContentAsn1Structure() throws CertificateGeneratorException {
        Asn1PrimitiveBitString keyUsageAsn1 = new Asn1PrimitiveBitString();
        keyUsageAsn1.setIdentifier("keyUsage");
        byte[] value = {0,0};
        if (digitalSignature) value[0] |= 1;
        if (nonRepudiation) value[0] |= 1 << 1;
        if (keyEncipherment) value[0] |= 1 << 2;
        if (dataEncipherment) value[0] |= 1 << 3;
        if (keyAgreement) value[0] |= 1 << 4;
        if (keyCertSign) value[0] |= 1 << 5;
        if (cRLSign) value[0] |= 1 << 6;
        if (encipherOnly) value[0] |= 1 << 7;
        if (decipherOnly) value[1] |= 1;
        keyUsageAsn1.setValue(value);
        keyUsageAsn1.setUnusedBits(7);

        byte[] derEncoded = Asn1EncoderForX509.encode(new Linker(new HashMap<>()), keyUsageAsn1);
        Asn1PrimitiveOctetString extensionValue = new Asn1PrimitiveOctetString();
        extensionValue.setValue(derEncoded);
        return extensionValue;
    }
}
