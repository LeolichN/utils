package utils.crypto.chameleon;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;

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
}
