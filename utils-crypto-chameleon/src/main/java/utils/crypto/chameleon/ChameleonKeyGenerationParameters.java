package utils.crypto.chameleon;

import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;

import java.security.SecureRandom;

/**
 * @author tsao
 * @version 0.1.0
 * @create 2022-05-05 18:03
 * @since 0.1.0
 **/
public class ChameleonKeyGenerationParameters  extends KeyGenerationParameters {

    private ECDomainParameters domainParameters;

    public ChameleonKeyGenerationParameters(SecureRandom secureRandom, ECDomainParameters domainParameters) {
        super(secureRandom, domainParameters.getN().bitLength());
        this.domainParameters = domainParameters;
    }

    public ECDomainParameters getDomainParameters() {
        return this.domainParameters;
    }
}
