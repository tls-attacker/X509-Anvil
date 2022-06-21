/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config.model;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;

import java.util.ArrayList;
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
