package org.example;
import static org.example.Tables.*;

public class DES {

        // funkcja implementujaca algorytm DES
        public static long algorithmDES(long block, long key, boolean encryption) {
            // permutacja poczatkowa wedlug tablicy initialPermutation
            long permutation = permutation(block, initialPermutation);

            // podzielenie na lewa i prawą polowe
            int leftHalf = (int) (permutation >> 32);
            int rightHalf = (int) permutation;

            // wygenerowanie podkluczy
            long[] subkeys = generateSubkeys(key);

            // 16 rund algorytmu
            for (int i = 0; i < 16; i++) {
                // zamiana polowek miejscami
                int temp = leftHalf;
                leftHalf = rightHalf;

                // jezeli deszyfrujemy to uzywamy podkluczy w odwroconej kolejnosci
                int subkeyIndex;
                if (encryption) {
                    subkeyIndex = i;
                } else {
                    subkeyIndex = 15 - i;
                }

                // ponowna zamiana polowek miejscami po 16 rundach
                rightHalf = temp ^ feistelFunction(rightHalf, subkeys[subkeyIndex]);
            }

            // zlaczenie polowek ze soba
            long combinedBlock = ((long) rightHalf << 32) | (leftHalf & 0xFFFFFFFFL);

            // koncowa permutacja bloku z tablica IP^(-1)
            return permutation(combinedBlock, finalPermutation);
        }

        private static long permutation(long block, int[] permutationTable) {
            long result = 0;

            for (int i = 0; i < 64; i++) {
                result |= ((block >> (64 - permutationTable[i])) & 1) << (63 - i);
            }
            return result;
        }

        private static int feistelFunction(int rightHalf, long subkey) {
            long expanded = 0;

            // rozszerzenie prawej czesci bloku do 48 bitow
            for (int i = 0; i < 48; i++) {
                expanded |= ((rightHalf >> (32 - expansionTable[i])) & 1L) << (47 - i);
            }

            // XOR z podkluczem z rundy
            long xor = expanded ^ subkey;

            // redukcja kazdej grupy z 6 na 4 bity za pomoca sBoxow
            int result = 0;
            for (int i = 0; i < 8; i++) {
                int index = (int) ((xor >> (42 - i * 6)) & 0x3F);
                int row = ((index & 0x20) >> 4) | (index & 0x01);
                int column = (index >> 1) & 0x0F;
                result = (result << 4) | sBox[i][row][column];
            }

            // mieszanie za pomoca tablicy permutacyjnej
            int permutation = 0;
            for (int i = 0; i < 32; i++) {
                permutation |= ((result >> (32 - permutationTable[i])) & 1) << (31 - i);
            }

            return permutation;
        }

        // stworzenie kluczy na kazda z 16 rund
        private static long[] generateSubkeys(long key) {
            long[] subkeys = new long[16];

            // redukcja klucza z 64 na 56 bitow
            long pc1 = 0;
            for (int i = 0; i < 56; i++) {
                pc1 |= ((key >> (64 - PC1[i])) & 1L) << (55 - i);
            }

            // podzielenie klucza na 28 bitowe polowki
            int leftHalfSubkey = (int) (pc1 >> 28);
            int rightHalfSubkey = (int) (pc1 & 0x0FFFFFFF);

            // 16 rund generowania podkluczy
            for (int i = 0; i < 16; i++) {
                // rotacja w lewo o 1 lub 2 pozycje w zaleznosci od rundy
                leftHalfSubkey = ((leftHalfSubkey << shifts[i]) | (leftHalfSubkey >>> (28 - shifts[i]))) & 0x0FFFFFFF;
                rightHalfSubkey = ((rightHalfSubkey << shifts[i]) | (rightHalfSubkey >>> (28 - shifts[i]))) & 0x0FFFFFFF;

                // zlaczenie polowek podklucza
                long combinedSubkey = ((long) leftHalfSubkey << 28) | rightHalfSubkey;

                // permutacja kompresujaca
                long subkey = 0;
                for (int j = 0; j < 48; j++) {
                    subkey |= ((combinedSubkey >> (56 - PC2[j])) & 1L) << (47 - j);
                }

                subkeys[i] = subkey;
            }

            return subkeys;
        }
}
