/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.x509.config.model;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;

public interface Asn1Structure<T extends Asn1Encodable> {
    T getAsn1Structure(String identifier) throws CertificateGeneratorException;
}
