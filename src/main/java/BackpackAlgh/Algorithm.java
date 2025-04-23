package BackpackAlgh;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Algorithm {

    public static BigInteger[] generateNandM(BigInteger[] privateKey) {
        BigInteger sum = BigInteger.ZERO;
        SecureRandom random = new SecureRandom();
        for (BigInteger value : privateKey) {
            sum = sum.add(value);
        }

        BigInteger m = sum.add(BigInteger.valueOf(random.nextInt(20) + 10));
        BigInteger n;

        do {
            n = new BigInteger(m.bitLength() - 1, random); // mniejsza niż m
        } while (!n.gcd(m).equals(BigInteger.ONE) || n.compareTo(BigInteger.ONE) <= 0);

        return new BigInteger[] { m, n };
    }

    private BigInteger[] generatePublicKey(BigInteger[] privateKey, BigInteger m, BigInteger n) {
        BigInteger[] publicKey = new BigInteger[privateKey.length];

        for (int i = 0; i < privateKey.length; i++) {
            publicKey[i] = privateKey[i].multiply(n).mod(m);
        }

        return publicKey;
    }



}
