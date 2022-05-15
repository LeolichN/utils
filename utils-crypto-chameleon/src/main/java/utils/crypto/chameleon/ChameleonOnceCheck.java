package utils.crypto.chameleon;

import com.jd.blockchain.ledger.BytesValue;
import com.jd.blockchain.ledger.TypedValue;
import com.jd.blockchain.transaction.DataAccountChameleonOnceCheck;

import java.math.BigInteger;

/**
 * @author tsao
 * @version 0.1.0
 * @create 2022-05-15 22:23
 * @since 0.1.0
 **/
public class ChameleonOnceCheck implements DataAccountChameleonOnceCheck {

    public BytesValue hashDataOnce(byte[] data,byte[] pubKey) {
        return TypedValue.fromBytes(ChameleonUtils.sign(data, BigInteger.ONE,pubKey));
    }
}
