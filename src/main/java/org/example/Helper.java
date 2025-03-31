package org.example;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class Helper {

    public static void encryptFile(String inputPath, String outputPath, long key) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(inputPath));

        int outputSize = ((data.length + 7) / 8) * 8;
        byte[] dataWithPadding = new byte[outputSize];
        System.arraycopy(data, 0, dataWithPadding, 0, data.length);

        int paddingSize = outputSize - data.length;
        for (int i = data.length; i < outputSize; i++) {
            dataWithPadding[i] = (byte) paddingSize;
        }

        try (FileOutputStream result = new FileOutputStream(outputPath)) {
            for (int i = 0; i < dataWithPadding.length; i += 8) {
                long byteBlock = 0;
                for (int j = 0; j < 8; j++) {
                    byteBlock = (byteBlock << 8) | (dataWithPadding[i + j] & 0xFF);
                }

                long encrypted = DES.algorithmDES(byteBlock, key, true);

                for (int j = 7; j >= 0; j--) {
                    result.write((byte) (encrypted >>> (j * 8)));
                }
            }
        }
    }

    public static void decryptFile(String inputPath, String outputPath, long key) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(inputPath));

        if (data.length % 8 != 0) {
            throw new IllegalArgumentException("Długość zaszyfrowanego pliku nie jest wielokrotnością 8 bajtów!");
        }

        byte[] encryptedData = new byte[data.length];

        for (int i = 0; i < data.length; i += 8) {
            long byteBlock = 0;
            for (int j = 0; j < 8; j++) {
                byteBlock = (byteBlock << 8) | (data[i + j] & 0xFF);
            }

            long encrypted = DES.algorithmDES(byteBlock, key, false);

            for (int j = 7; j >= 0; j--) {
                encryptedData[i + (7-j)] = (byte) (encrypted >>> (j * 8));
            }
        }

        int paddingSize = encryptedData[encryptedData.length - 1] & 0xFF;
        if (paddingSize > 0 && paddingSize <= 8) {
            boolean correctPadding = true;

            for (int i = encryptedData.length - paddingSize; i < encryptedData.length; i++) {
                if ((encryptedData[i] & 0xFF) != paddingSize) {
                    correctPadding = false;
                    break;
                }
            }

            if (correctPadding) {
                Files.write(Paths.get(outputPath),
                        Arrays.copyOf(encryptedData, encryptedData.length - paddingSize));
            } else {
                Files.write(Paths.get(outputPath), encryptedData);
            }
        } else {
            Files.write(Paths.get(outputPath), encryptedData);
        }
    }

    public static String encryptText(String string, long key) {
        StringBuilder resultHex = new StringBuilder();

        for (int i = 0; i < string.length(); i += 8) {
            StringBuilder block = new StringBuilder(string.substring(i, Math.min(i + 8, string.length())));

            while (block.length() < 8) {
                block.append('\0');
            }

            long byteBlock = 0;
            for (int j = 0; j < 8; j++) {
                byteBlock = (byteBlock << 8) | (block.charAt(j) & 0xFF);
            }

            long encrypted = DES.algorithmDES(byteBlock, key, true);
            resultHex.append(String.format("%016X ", encrypted));
        }

        return resultHex.toString();
    }

    public static String decryptText(String ciphertextString, long key) {
        StringBuilder result = new StringBuilder();

        String[] blocks = ciphertextString.split("\\s+");
        for (String blocskHex : blocks) {
            if (blocskHex.isEmpty()) continue;

            long byteBlock = Long.parseUnsignedLong(blocskHex, 16);
            long decrypted = DES.algorithmDES(byteBlock, key, false);

            for (int i = 7; i >= 0; i--) {
                char chr = (char) ((decrypted >>> (i * 8)) & 0xFF);

                if (chr != '\0') {
                    result.append(chr);
                }
            }
        }

        return result.toString();
    }
}
