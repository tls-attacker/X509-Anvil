/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.x509.config.model;

import de.rub.nds.asn1.model.Asn1PrimitiveIa5String;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Name implements Asn1Structure<Asn1Sequence> {
    private List<RelativeDistinguishedName> relativeDistinguishedNames;

    public Name(List<RelativeDistinguishedName> relativeDistinguishedNames) {
        this.relativeDistinguishedNames = relativeDistinguishedNames;
    }

    public Name() {
        this.relativeDistinguishedNames = new ArrayList<>();
    }

    public List<RelativeDistinguishedName> getRelativeDistinguishedNames() {
        return relativeDistinguishedNames;
    }

    public void setRelativeDistinguishedNames(List<RelativeDistinguishedName> relativeDistinguishedNames) {
        this.relativeDistinguishedNames = relativeDistinguishedNames;
    }

    public void addRelativeDistinguishedName(RelativeDistinguishedName relativeDistinguishedName) {
        this.relativeDistinguishedNames.add(relativeDistinguishedName);
    }

    public void addNameComponent(String oid, String value, DirectoryStringType directoryStringType) {
        AttributeTypeAndValue attributeTypeAndValue =
            new AttributeTypeAndValue(oid, X509Util.getDirectoryString(value, directoryStringType));
        RelativeDistinguishedName rdn = new RelativeDistinguishedName(Collections.singletonList(attributeTypeAndValue));
        addRelativeDistinguishedName(rdn);
    }

    public void addDomainComponents(String... componentValues) {
        RelativeDistinguishedName rdn = new RelativeDistinguishedName();
        for (String value : componentValues) {
            Asn1PrimitiveIa5String ia5String = new Asn1PrimitiveIa5String();
            ia5String.setValue(value);
            AttributeTypeAndValue attributeTypeAndValue =
                new AttributeTypeAndValue(AttributeTypeObjectIdentifiers.DOMAIN_COMPONENT, ia5String);
            rdn.addAttributeTypeAndValue(attributeTypeAndValue);
        }
        addRelativeDistinguishedName(rdn);
    }

    public void setCn(String value, DirectoryStringType directoryStringType) {
        // Remove existing cn
        for (RelativeDistinguishedName rdn : relativeDistinguishedNames) {
            if (rdn.getAttributeTypeAndValueList().get(0).getType()
                .equals(AttributeTypeObjectIdentifiers.COMMON_NAME)) {
                relativeDistinguishedNames.remove(rdn);
                break;
            }
        }

        RelativeDistinguishedName cn = new RelativeDistinguishedName();
        cn.addAttributeTypeAndValue(new AttributeTypeAndValue(AttributeTypeObjectIdentifiers.COMMON_NAME,
            X509Util.getDirectoryString(value, directoryStringType)));
        relativeDistinguishedNames.add(cn);
    }

    public Asn1Sequence getAsn1Structure(String identifier) throws CertificateGeneratorException {
        Asn1Sequence name = new Asn1Sequence();
        name.setIdentifier(identifier);

        int index = 0;
        for (RelativeDistinguishedName rdn : relativeDistinguishedNames) {
            Asn1Set relativeDistinguishedName = rdn.getAsn1Structure("relativeDistinguishedName" + index++);
            name.addChild(relativeDistinguishedName);
        }

        return name;
    }
}
