package de.rub.nds.x509.config.model;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.exception.CertificateGeneratorException;

import java.util.ArrayList;
import java.util.List;

public class RelativeDistinguishedName implements Asn1Structure<Asn1Set> {
    private List<AttributeTypeAndValue> attributeTypeAndValueList;

    public RelativeDistinguishedName(List<AttributeTypeAndValue> attributeTypeAndValueList) {
        this.attributeTypeAndValueList = attributeTypeAndValueList;
    }

    public RelativeDistinguishedName() {
        this.attributeTypeAndValueList = new ArrayList<>();
    }

    public List<AttributeTypeAndValue> getAttributeTypeAndValueList() {
        return attributeTypeAndValueList;
    }

    public void setAttributeTypeAndValueList(List<AttributeTypeAndValue> attributeTypeAndValueList) {
        this.attributeTypeAndValueList = attributeTypeAndValueList;
    }

    public void addAttributeTypeAndValue(AttributeTypeAndValue attributeTypeAndValue) {
        this.attributeTypeAndValueList.add(attributeTypeAndValue);
    }

    @Override
    public Asn1Set getAsn1Structure(String identifier) throws CertificateGeneratorException {
        Asn1Set relativeDistinguishedName = new Asn1Set();
        relativeDistinguishedName.setIdentifier(identifier);

        int index = 0;
        for (AttributeTypeAndValue atv : attributeTypeAndValueList) {
            Asn1Sequence attributeTypeAndValue = atv.getAsn1Structure("attributeTypeAndValue" + index++);
            relativeDistinguishedName.addChild(attributeTypeAndValue);
        }

        return relativeDistinguishedName;
    }
}
