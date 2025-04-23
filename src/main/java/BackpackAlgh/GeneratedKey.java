package BackpackAlgh;

import java.math.BigInteger;
import java.security.SecureRandom;

public class GeneratedKey {

    private final SecureRandom random = new SecureRandom();
    private BigInteger[] privateKey;
    private BigInteger[] publicKey;
    private BigInteger m;
    private BigInteger n;

    public GeneratedKey(){
        this.privateKey = generate();
        generateNandM();
        this.publicKey = generatePublicKey();
    }
    private BigInteger[] generate() {
        SecureRandom rand = new SecureRandom();
        BigInteger[] key = new BigInteger[8];

        // Pierwszy element - losowy, ale niezerowy
        key[0] = new BigInteger("1").add(new BigInteger(5, rand)); // np. losowe z zakresu 1–32

        BigInteger sum = key[0];

        for (int i = 1; i < 8; i++) {
            // Dodaj losowy przyrost do sumy, aby zapewnić superrosnący ciąg
            BigInteger increment = new BigInteger(String.valueOf(rand.nextInt(15) + 1));
            key[i] = sum.add(increment);
            sum = sum.add(key[i]); // aktualizuj sumę
        }

        return key;
    }

    public void generateNandM () {
        BigInteger sum = BigInteger.ZERO;
        for (BigInteger value : privateKey) {
            sum = sum.add(value);
        }

        m = sum.add(BigInteger.valueOf(random.nextInt(20) + 10));

        do {
            n = new BigInteger(m.bitLength() - 1, random); // mniejsza niż m
        } while (!n.gcd(m).equals(BigInteger.ONE) || n.compareTo(BigInteger.ONE) <= 0);
    }

    private  BigInteger[] generatePublicKey() {
        // Inicjalizacja tablicy klucza publicznego o tym samym rozmiarze co klucz prywatny
        publicKey = new BigInteger[privateKey.length];

        // Obliczanie każdego elementu klucza publicznego
        for (int i = 0; i < privateKey.length; i++) {
            // Wzór: publicKey[i] = (privateKey[i] * n) mod m
            publicKey[i] = privateKey[i].multiply(n).mod(m);
        }
        return publicKey;
    }

    public BigInteger getM() {
        return m;
    }

    public BigInteger getN() {
        return n;
    }
}
