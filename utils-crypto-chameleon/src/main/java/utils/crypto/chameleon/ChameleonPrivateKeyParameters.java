package utils.crypto.chameleon;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author tsao
 * @version 0.1.0
 * @create 2022-05-05 17:48
 * @since 0.1.0
 **/
public class ChameleonPrivateKeyParameters extends ECKeyParameters {
    private BigInteger k;
    private BigInteger x;

    public ChameleonPrivateKeyParameters(BigInteger k, BigInteger x, ECDomainParameters parameters){
        super(true,parameters);
        this.k = parameters.validatePrivateScalar(k);
        this.x = parameters.validatePrivateScalar(x);
    }

    public BigInteger getK() {
        return k;
    }

    public BigInteger getX() {
        return x;
    }
}
