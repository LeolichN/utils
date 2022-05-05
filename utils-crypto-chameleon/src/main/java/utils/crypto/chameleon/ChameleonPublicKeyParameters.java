package utils.crypto.chameleon;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * @author tsao
 * @version 0.1.0
 * @create 2022-05-05 17:55
 * @since 0.1.0
 **/
public class ChameleonPublicKeyParameters extends ECKeyParameters {

    private final ECPoint K;
    private final ECPoint Y;

    public ChameleonPublicKeyParameters(ECPoint K,ECPoint Y, ECDomainParameters parameters) {
        super(false, parameters);
        this.K = parameters.validatePublicPoint(K);
        this.Y = parameters.validatePublicPoint(Y);
    }

    public ECPoint getK() {
        return this.K;
    }

    public ECPoint getY() {
        return this.Y;
    }
}
