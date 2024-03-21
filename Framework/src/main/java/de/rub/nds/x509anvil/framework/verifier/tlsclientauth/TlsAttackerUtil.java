/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.verifier.tlsclientauth;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;

public class TlsAttackerUtil {
    public static SignatureAndHashAlgorithm translateSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm)
        throws VerifierException {
        switch (signatureAlgorithm) {
            // case RSA_NONE: return SignatureAndHashAlgorithm.RSA_SHA256;
            case RSA_SHA1:
                return SignatureAndHashAlgorithm.RSA_SHA1;
            case RSA_SHA224:
                return SignatureAndHashAlgorithm.RSA_SHA224;
            case RSA_SHA256:
                return SignatureAndHashAlgorithm.RSA_SHA256;
            case RSA_SHA384:
                return SignatureAndHashAlgorithm.RSA_SHA384;
            case RSA_SHA512:
                return SignatureAndHashAlgorithm.RSA_SHA512;
            case RSA_MD5:
            case RSA_MD2:
            case RSA_MD4:
                return SignatureAndHashAlgorithm.RSA_MD5;
            // case DSA_NONE: return SignatureAndHashAlgorithm.DSA_SHA256;
            case DSA_SHA1:
                return SignatureAndHashAlgorithm.DSA_SHA1;
            case DSA_SHA224:
                return SignatureAndHashAlgorithm.DSA_SHA224;
            case DSA_SHA256:
                return SignatureAndHashAlgorithm.DSA_SHA256;
            case DSA_SHA384:
                return SignatureAndHashAlgorithm.DSA_SHA384;
            case DSA_SHA512:
                return SignatureAndHashAlgorithm.DSA_SHA512;
            // case ECDSA_NONE: return SignatureAndHashAlgorithm.ECDSA_SHA256;
            case ECDSA_SHA1:
                return SignatureAndHashAlgorithm.ECDSA_SHA1;
            case ECDSA_SHA224:
                return SignatureAndHashAlgorithm.ECDSA_SHA224;
            case ECDSA_SHA256:
                return SignatureAndHashAlgorithm.ECDSA_SHA256;
            case ECDSA_SHA384:
                return SignatureAndHashAlgorithm.ECDSA_SHA384;
            case ECDSA_SHA512:
                return SignatureAndHashAlgorithm.ECDSA_SHA512;
            default:
                throw new VerifierException("Unsupported signature algorithm");
        }
    }
}
