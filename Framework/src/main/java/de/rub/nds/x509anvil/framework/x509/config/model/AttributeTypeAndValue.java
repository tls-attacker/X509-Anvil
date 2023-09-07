/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config.model;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;

import jakarta.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;

public class AttributeTypeAndValue implements Asn1Structure<Asn1Sequence> {
    private String type;
    private Asn1Encodable value;

    public AttributeTypeAndValue(String type, Asn1Encodable value) {
        this.type = type;
        this.value = value;
    }

    public String getType() {
        return type;
    }

    public Asn1Encodable getValue() {
        return value;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setValue(Asn1Encodable value) {
        this.value = value;
    }

    @Override
    public Asn1Sequence getAsn1Structure(String identifier) throws CertificateGeneratorException {
        Asn1Sequence attributeTypeAndValue = new Asn1Sequence();
        attributeTypeAndValue.setIdentifier(identifier);

        Asn1ObjectIdentifier typeOid = new Asn1ObjectIdentifier();
        typeOid.setIdentifier("type");
        typeOid.setValue(this.type);
        attributeTypeAndValue.addChild(typeOid);

        try {
            Asn1Encodable valueAsn1 = this.value.getCopy();
            valueAsn1.setIdentifier("value");
            attributeTypeAndValue.addChild(valueAsn1);
        } catch (XMLStreamException | JAXBException | IOException e) {
            throw new CertificateGeneratorException("Unable to copy value of attributeTypeAndValue", e);
        }

        return attributeTypeAndValue;
    }
}
