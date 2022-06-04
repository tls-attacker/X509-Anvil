package de.rub.nds.util;

import de.rub.nds.constants.KeyType;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;

public class PemUtil {
    public static byte[] encodeKeyAsPem(byte[] keyDer, KeyType keyType, boolean isPrivate) throws IOException {
        String privateOrPublic = isPrivate ? " PRIVATE " : " PUBLIC ";
        PemObject pemObject = new PemObject(keyType.name() + privateOrPublic + "KEY", keyDer);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(stream));
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        return stream.toByteArray();
    }
}
