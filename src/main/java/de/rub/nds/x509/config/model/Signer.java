package de.rub.nds.x509.config.model;

public enum Signer {
    NEXT_IN_CHAIN,          // Use private key of next ca certificate in chain
    SELF,                   // Use own private key
    OVERRIDE                // Use unrelated private key supplied via config
}
