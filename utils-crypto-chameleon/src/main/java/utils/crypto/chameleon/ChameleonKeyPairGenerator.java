package utils.crypto.chameleon;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author tsao
 * @version 0.1.0
 * @create 2022-05-05 17:46
 * @since 0.1.0
 **/
public class ChameleonKeyPairGenerator  implements AsymmetricCipherKeyPairGenerator {

    private SecureRandom random;

    private ECDomainParameters domainParameters;

    public ChameleonKeyPairGenerator(){

    }

    public void init(KeyGenerationParameters keyGenerationParameters) {
        ChameleonKeyGenerationParameters parameters = ((ChameleonKeyGenerationParameters) keyGenerationParameters);
        this.random = keyGenerationParameters.getRandom();
        this.domainParameters = parameters.getDomainParameters();
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        BigInteger n = this.domainParameters.getN();
        int bitLength = n.bitLength();
        BigInteger k = generateRandomBigInteger(n,bitLength);
        BigInteger x = generateRandomBigInteger(n,bitLength);

        ChameleonPrivateKeyParameters priKey = new ChameleonPrivateKeyParameters(k,x,this.domainParameters);
        ECPoint K = createBasePointMultiplier().multiply(this.domainParameters.getG(), k);
        ECPoint Y = createBasePointMultiplier().multiply(this.domainParameters.getG(), x);
        return new AsymmetricCipherKeyPair(new ChameleonPublicKeyParameters(K,Y,domainParameters),priKey);
    }

    private BigInteger generateRandomBigInteger(BigInteger N,int bitLength){
        int nafWeight = bitLength>>2;
        BigInteger randomInt = BigIntegers.createRandomBigInteger(bitLength, this.random);
        while(randomInt.compareTo(N) >= 0 || WNafUtil.getNafWeight(randomInt) < nafWeight){
            randomInt = BigIntegers.createRandomBigInteger(bitLength, this.random);
        }
        return randomInt;
    }

    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }
}
