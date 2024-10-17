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
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

public class TlsAttackerUtil {
    public static SignatureAndHashAlgorithm translateSignatureAlgorithm(X509SignatureAlgorithm signatureAlgorithm)
        throws VerifierException {
        switch (signatureAlgorithm) {
            case MD5_WITH_RSA_ENCRYPTION:
                return SignatureAndHashAlgorithm.RSA_MD5;
            case SHA1_WITH_RSA_ENCRYPTION:
                return SignatureAndHashAlgorithm.RSA_SHA1;
            case SHA256_WITH_RSA_ENCRYPTION:
                return SignatureAndHashAlgorithm.RSA_SHA256;
            case SHA384_WITH_RSA_ENCRYPTION:
                return SignatureAndHashAlgorithm.RSA_SHA384;
            case SHA512_WITH_RSA_ENCRYPTION:
                return SignatureAndHashAlgorithm.RSA_SHA512;
            case SHA224_WITH_RSA_ENCRYPTION:
                return SignatureAndHashAlgorithm.RSA_SHA224;
            case DSA_WITH_SHA1:
                return SignatureAndHashAlgorithm.DSA_SHA1;
            case DSA_WITH_SHA224:
                return SignatureAndHashAlgorithm.DSA_SHA224;
            case DSA_WITH_SHA256:
                return SignatureAndHashAlgorithm.DSA_SHA256;
            case DSA_WITH_SHA384:
                return SignatureAndHashAlgorithm.DSA_SHA384;
            case DSA_WITH_SHA512:
                return SignatureAndHashAlgorithm.DSA_SHA512;
            case ECDSA_WITH_SHA1:
                return SignatureAndHashAlgorithm.ECDSA_SHA1;
            case ECDSA_WITH_SHA224:
                return SignatureAndHashAlgorithm.ECDSA_SHA224;
            case ECDSA_WITH_SHA256:
                return SignatureAndHashAlgorithm.ECDSA_SHA256;
            case ECDSA_WITH_SHA384:
                return SignatureAndHashAlgorithm.ECDSA_SHA384;
            case ECDSA_WITH_SHA512:
                return SignatureAndHashAlgorithm.ECDSA_SHA512;
            case RSASSA_PSS:
            case MD2_WITH_RSA_ENCRYPTION:
            case MD4_WITH_RSA_ENCRYPTION:
            default:
                throw new VerifierException("Unsupported signature algorithm");
        }
    }
}
