package de.rub.nds.x509anvil.x509.config.model;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.x509anvil.exception.CertificateGeneratorException;

public interface Asn1Structure<T extends Asn1Encodable> {
    T getAsn1Structure(String identifier) throws CertificateGeneratorException;
}
