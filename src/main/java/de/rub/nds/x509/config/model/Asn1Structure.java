package de.rub.nds.x509.config.model;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.exception.CertificateGeneratorException;

public interface Asn1Structure<T extends Asn1Encodable> {
    T getAsn1Structure(String identifier) throws CertificateGeneratorException;
}
