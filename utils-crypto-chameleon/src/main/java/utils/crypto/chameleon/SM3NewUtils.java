package utils.crypto.chameleon;


import org.bouncycastle.crypto.digests.SM3Digest;
import utils.security.Hasher;

/**
 * 采用“哈希法”生成伪随机数；
 * 
 * @author huanghaiquan
 *
 */
public abstract class SM3NewUtils {
    // The length of sm3 output is 32 bytes
    public static final int SM3DIGEST_LENGTH = 32;

    public static byte[] hash(byte[] data) {

        byte[] result = new byte[SM3DIGEST_LENGTH];

        SM3NewDigest sm3digest = new SM3NewDigest();

        sm3digest.update(data, 0, data.length);
        sm3digest.doFinal(result, 0);

        return result;
    }

    public static byte[] hash(byte[] data, int offset, int len) {

        byte[] result = new byte[SM3DIGEST_LENGTH];

        SM3NewDigest sm3digest = new SM3NewDigest();

        sm3digest.update(data, offset, len);
        sm3digest.doFinal(result, 0);

        return result;
    }


    public static Hasher beginHash() {
        return new SM3NewHasher();
    }

    private static class SM3NewHasher implements Hasher{

        private SM3NewDigest digest = new SM3NewDigest();

        public void update(byte[] bytes) {
            digest.update(bytes, 0, bytes.length);
        }

        public void update(byte[] bytes, int offset, int len) {
            digest.update(bytes, offset, len);
        }

        public byte[] complete() {
            byte[] result = new byte[SM3DIGEST_LENGTH];
            digest.doFinal(result, 0);
            return result;
        }

    }
}