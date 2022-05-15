package utils.crypto.chameleon;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import utils.crypto.chameleon.sm3new.SM3NewUtils;
import utils.io.BytesUtils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author tsao
 * @version 0.1.0
 * @create 2022-05-05 17:39
 * @since 0.1.0
 **/
public class ChameleonUtils {

    public static final int PRIVKEY_SIZE = 32;

    public static final int COORDS_SIZE = 32;
    public static final int POINT_SIZE = COORDS_SIZE * 2 + 1;

    public static final int R_SIZE = 32;
    public static final int S_SIZE = 32;

    private static final ECNamedCurveParameterSpec PARAMS = ECNamedCurveTable.getParameterSpec("secp256k1");
    private static final ECCurve CURVE = PARAMS.getCurve();

    public static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(CURVE, PARAMS.getG(), PARAMS.getN(),
            PARAMS.getH());


    public static AsymmetricCipherKeyPair generateKeyPair(SecureRandom secureRandom){
        ChameleonKeyGenerationParameters keyGenerationParameters = new ChameleonKeyGenerationParameters(secureRandom,DOMAIN_PARAMS);
        ChameleonKeyPairGenerator keyPairGenerator = new ChameleonKeyPairGenerator();

        keyPairGenerator.init(keyGenerationParameters);
        return keyPairGenerator.generateKeyPair();

    }

    public static byte[] retrievePublicKey(byte[] rawPrivKeyBytes) {
        byte[] privK = ByteUtils.subArray(rawPrivKeyBytes,0,32);
        byte[] privX = ByteUtils.subArray(rawPrivKeyBytes,32,64);
        ECPoint pubKeyK = DOMAIN_PARAMS.getG().multiply(new BigInteger(1,privK)).normalize();
        ECPoint pubKeyY = DOMAIN_PARAMS.getG().multiply(new BigInteger(1,privX)).normalize();
        byte[] pubKeyBytesK = pubKeyK.getEncoded(false);
        byte[] pubKeyBytesY = pubKeyY.getEncoded(false);
        return BytesUtils.concat(pubKeyBytesK,pubKeyBytesY);
    }

    public static byte[] sign(byte[] data,BigInteger rho,byte[] publicKey){
        byte[] K = ByteUtils.subArray(publicKey,0,65);
        byte[] X = ByteUtils.subArray(publicKey,65,130);
        ECPoint pointK = DOMAIN_PARAMS.getCurve().decodePoint(K);
        ECPoint pointX = DOMAIN_PARAMS.getCurve().decodePoint(X);

        ECPoint mp = DOMAIN_PARAMS.getG().multiply(new BigInteger(1,SM3NewUtils.hash(BytesUtils.concat(data,K))));
        ECPoint rY = pointX.multiply(rho);
        return mp.add(rY).getEncoded(false);
    }

    public static boolean verify(byte[] data,BigInteger rho,byte[] publicKey,byte[] signature){
        return BytesUtils.equals(signature,sign(data, rho, publicKey));
    }

}
