package ba2;

import java.math.BigInteger;
import java.security.SecureRandom;

public class GeneratedKey {
    private final SecureRandom random = new SecureRandom();
    private BigInteger[] privateKey;
    private BigInteger[] publicKey;
    private BigInteger m;
    private BigInteger n;
    private Algorithm algorithm;

    public GeneratedKey() {
        this.algorithm = new Algorithm();
        this.privateKey = generateSuperIncreasingSequence();
        BigInteger[] nm = algorithm.generateNandM(privateKey);
        this.m = nm[0];
        this.n = nm[1];
        this.publicKey = algorithm.generatePublicKey(privateKey, m, n);
    }

    /**
     * Konstruktor przyjmujący istniejący klucz prywatny
     */
    public GeneratedKey(BigInteger[] privateKey) {
        this.algorithm = new Algorithm();

        if (!algorithm.isSuperIncreasing(privateKey)) {
            throw new IllegalArgumentException("Klucz prywatny musi być ciągiem superrosnącym");
        }

        this.privateKey = privateKey;
        BigInteger[] nm = algorithm.generateNandM(privateKey);
        this.m = nm[0];
        this.n = nm[1];
        this.publicKey = algorithm.generatePublicKey(privateKey, m, n);
    }

    private BigInteger[] generateSuperIncreasingSequence() {
        BigInteger[] key = new BigInteger[8];

        // Pierwszy element - mała, losowa liczba
        key[0] = new BigInteger(8, random).add(BigInteger.ONE);

        BigInteger sum = key[0];

        for (int i = 1; i < 8; i++) {
            // Każdy następny element jest większy niż suma wszystkich poprzednich
            BigInteger increment = sum.multiply(BigInteger.valueOf(2));
            key[i] = sum.add(increment);
            sum = sum.add(key[i]);
        }

        return key;
    }

    public BigInteger encrypt(int[] message) {
        return algorithm.encrypt(message, publicKey);
    }

    public int[] decrypt(BigInteger encrypted) {
        return algorithm.decrypt(encrypted, privateKey, m, n);
    }

    // Gettery
    public BigInteger[] getPrivateKey() {
        return privateKey;
    }

    public BigInteger[] getPublicKey() {
        return publicKey;
    }

    public BigInteger getM() {
        return m;
    }

    public BigInteger getN() {
        return n;
}}
