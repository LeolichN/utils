package utils.crypto.adv.bulletproof.innerproduct;

import cyclops.collections.mutable.ListX;
import utils.crypto.adv.bulletproof.VerificationFailedException;
import utils.crypto.adv.bulletproof.Verifier;
import utils.crypto.adv.bulletproof.algebra.GroupElement;
import utils.crypto.adv.bulletproof.linearalgebra.VectorBase;
import utils.crypto.adv.bulletproof.util.ProofUtils;

import java.math.BigInteger;
import java.util.*;

/**
 * Created by buenz on 6/29/17.
 * This class provides an efficient inner product verifier by only using n group exponentations instead of n log(n). It however currently only works for {@link VectorBase}s of size 2^k for some k.
 */
public class EfficientInnerProductVerifier<T extends GroupElement<T>> implements Verifier<VectorBase<T>, T, InnerProductProof<T>> {
    /**
     * Only works if params has size 2^k for some k.
     */
    @Override
    public void verify(VectorBase<T> params, T c, InnerProductProof<T> proof, Optional<BigInteger> salt) throws VerificationFailedException {
        List<T> ls = proof.getL();
        List<T> rs = proof.getR();
        List<BigInteger> challenges = new ArrayList<>(ls.size());
        BigInteger q = params.getGs().getGroup().groupOrder();
        BigInteger previousChallenge = salt.orElse(BigInteger.ZERO);
        for (int i = 0; i < ls.size(); ++i) {
            T l = ls.get(i);
            T r = rs.get(i);
            BigInteger x = ProofUtils.computeChallenge(q, previousChallenge, l, r);
            challenges.add(x);
            BigInteger xInv = x.modInverse(q);

            c = l.multiply(x.pow(2)).add(r.multiply(xInv.pow(2))).add(c);
            previousChallenge = x;

        }
        int n = params.getGs().size();
        BigInteger[] otherExponents = new BigInteger[n];

        otherExponents[0] = challenges.stream().reduce(BigInteger.ONE, (l, r) -> l.multiply(r).mod(q)).modInverse(q);
        BitSet bitSet = new BitSet();
        Collections.reverse(challenges);
        for (int i = 0; i < n / 2; ++i) {
            for (int j = 0; (1 << j) + i < n; ++j) {

                int i1 = i + (1 << j);
                if (bitSet.get(i1)) {

                } else {
                    otherExponents[i1] = otherExponents[i].multiply(challenges.get(j).pow(2)).mod(q);
                    bitSet.set(i1);
                }
            }
        }
        List<BigInteger> challengeVector2 = new ArrayList<>();
        for (int i = 0; i < n; ++i) {
            BigInteger bigIntI = BigInteger.valueOf(i);
            BigInteger ithChallenge = BigInteger.ONE;
            for (int j = 0; j < challenges.size(); ++j) {
                if (bigIntI.testBit(j)) {
                    ithChallenge = ithChallenge.multiply(challenges.get(j)).mod(q);
                } else {
                    ithChallenge = ithChallenge.multiply(challenges.get(j).modInverse(q)).mod(q);

                }
            }
            challengeVector2.add(ithChallenge);
        }

        ListX<BigInteger> challengeVector = ListX.of(otherExponents);
        ListX<BigInteger> sleft = challengeVector.map(proof.getA()::multiply);
        ListX<BigInteger> sright = challengeVector.reverse().map(proof.getB()::multiply);

        BigInteger prod = proof.getA().multiply(proof.getB()).mod(q);
        T g = params.getGs().commit(sleft);

        T h = params.getHs().commit(sright);
        T cProof = g.add(h).add(params.getH().multiply(prod));

        equal(c, cProof, "cTotal (%s) not equal to cProof (%s)");
    }
}
