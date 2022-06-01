package de.rub.nds.x509.config.model;

public enum IssuerType {
    NEXT_IN_CHAIN,          // Issuer field is identical to Subject of next cert in chain
    SELF,                   // Issuer field is identical to the certificate's own Subject field
    OVERRIDE,               // Use unrelated issuer
}
