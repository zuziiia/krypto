package DESX;

public class DESX {

    // Szyfrowanie DESX
    public static long encryptDESX(long plaintext, long keyK1, long keyK2, long keyK3) {
        // XOR z kluczem wejściowym (K2)
        long inputXor = plaintext ^ keyK2;

        // DES z kluczem głównym (K1)
        long encrypted = DES.algorithmDES(inputXor, keyK1, true);

        // XOR z kluczem wyjściowym (K3)
        return encrypted ^ keyK3;
    }

    // Deszyfrowanie DESX
    public static long decryptDESX(long ciphertext, long keyK1, long keyK2, long keyK3) {
        // XOR z kluczem wyjściowym (K3)
        long outputXor = ciphertext ^ keyK3;

        // DES z kluczem głównym (K1), w trybie deszyfrowania
        long decrypted = DES.algorithmDES(outputXor, keyK1, false);

        // XOR z kluczem wejściowym (K2)
        return decrypted ^ keyK2;
    }
}
