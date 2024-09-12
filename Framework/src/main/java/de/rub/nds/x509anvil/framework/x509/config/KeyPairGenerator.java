package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.protocol.crypto.key.*;
import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithmLengthPair;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Random;

import static de.rub.nds.x509attacker.constants.X509NamedCurve.*;


/**
 * Wraps around the key Generator in the Protocol-Attacker
 */
public class KeyPairGenerator {

    public static long RANDOM_SEED = 123456789;
    public static Random random = new Random(RANDOM_SEED);

    public static void generateNewKeys(SignatureAlgorithmLengthPair algorithmLengthPair, X509CertificateConfig config) {
        switch (algorithmLengthPair) {
            case RSA_512:
            case RSA_1024:
            case DSA_2048:
            case RSA_4096:
                Pair<RsaPublicKey, RsaPrivateKey> keyPair = KeyGenerator.generateRsaKeys(config.getDefaultSubjectRsaPublicExponent(), algorithmLengthPair.getKeyLength(), random);
                config.setDefaultSubjectRsaModulus(keyPair.getLeft().getModulus());
                config.setDefaultSubjectRsaPrivateKey(keyPair.getRight().getPrivateExponent());
                break;
            case DSA_512:
            case DSA_1024:
            case RSA_2048:
            case DSA_3072:
                DsaPublicKey dsaPublicKey = KeyGenerator.generateDsaPublicKey(config.getDefaultSubjectDsaPrivateKeyX(), algorithmLengthPair.getKeyLength(), 160, random);
                config.setDefaultSubjectDsaPrimeP(dsaPublicKey.getModulus());
                config.setDefaultSubjectDsaGenerator(dsaPublicKey.getGenerator());
                config.setDefaultSubjectDsaPrimeQ(dsaPublicKey.getQ());
                config.setDefaultSubjectDsaPublicKey(dsaPublicKey.getY());
                break;
            case ECDSA_160:
            case ECDSA_224:
            case ECDSA_256:
            case ECDSA_384:
                config.setDefaultNamedCurve(curveFromAlgorithmLengthPair(algorithmLengthPair));
                EcdsaPublicKey ecdsaPublicKey = KeyGenerator.generateEcdsaPublicKey(config.getDefaultSubjectEcPrivateKey(), config.getDefaultNamedCurve().getParameters());
                config.setDefaultSubjectEcPublicKey(ecdsaPublicKey.getPublicPoint());
                break;
        }
    }

    private static X509NamedCurve curveFromAlgorithmLengthPair(SignatureAlgorithmLengthPair pair) {
        switch (pair) {
            case ECDSA_160:
                return SECP160R1;
            case ECDSA_224:
                return SECP224R1;
            case ECDSA_256:
                return SECP256R1;
            case ECDSA_384:
                return SECP384R1;
        }
    }
}
