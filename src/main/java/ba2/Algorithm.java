package ba2;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Algorithm {
    private final SecureRandom random = new SecureRandom();

    public BigInteger[] generateNandM(BigInteger[] privateKey) {
        BigInteger sum = BigInteger.ZERO;
        for (BigInteger value : privateKey) {
            sum = sum.add(value);
        }

        // m musi być większe niż suma wszystkich elementów klucza prywatnego
        BigInteger m = sum.add(BigInteger.valueOf(random.nextInt(20) + 10));
        BigInteger n;

        do {
            n = new BigInteger(m.bitLength() - 1, random);
        } while (!n.gcd(m).equals(BigInteger.ONE) || n.compareTo(BigInteger.ONE) <= 0);

        return new BigInteger[] { m, n };
    }

    public BigInteger[] generatePublicKey(BigInteger[] privateKey, BigInteger m, BigInteger n) {
        BigInteger[] publicKey = new BigInteger[privateKey.length];

        for (int i = 0; i < privateKey.length; i++) {
            publicKey[i] = privateKey[i].multiply(n).mod(m);
        }

        return publicKey;
    }

    public BigInteger encrypt(int[] message, BigInteger[] publicKey) {
        if (message.length != publicKey.length) {
            throw new IllegalArgumentException("Długość wiadomości musi być równa długości klucza publicznego");
        }

        BigInteger result = BigInteger.ZERO;

        for (int i = 0; i < message.length; i++) {
            if (message[i] == 1) {
                result = result.add(publicKey[i]);
            } else if (message[i] != 0) {
                throw new IllegalArgumentException("Wiadomość musi zawierać tylko 0 i 1");
            }
        }

        return result;
    }

    public int[] decrypt(BigInteger encrypted, BigInteger[] privateKey, BigInteger m, BigInteger n) {
        int[] message = new int[privateKey.length];

        // Obliczamy odwrotność n modulo m
        BigInteger nInverse = n.modInverse(m);

        // Przekształcamy zaszyfrowaną wartość
        BigInteger transformed = encrypted.multiply(nInverse).mod(m);

        // Rozwiązujemy problem plecakowy od końca
        for (int i = privateKey.length - 1; i >= 0; i--) {
            if (transformed.compareTo(privateKey[i]) >= 0) {
                message[i] = 1;
                transformed = transformed.subtract(privateKey[i]);
            } else {
                message[i] = 0;
            }
        }

        return message;
    }

    public boolean isSuperIncreasing(BigInteger[] privateKey) {
        BigInteger sum = BigInteger.ZERO;

        for (BigInteger value : privateKey) {
            if (value.compareTo(sum) <= 0 && !sum.equals(BigInteger.ZERO)) {
                return false;
            }
            sum = sum.add(value);
        }

        return true;
    }
}
