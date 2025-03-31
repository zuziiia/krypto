package org.example;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.file.Files;

public class DESXGUI extends JFrame {

    private JTextField inputField;
    private JTextField key1Field;
    private JTextField key2Field;
    private JTextField key3Field;
    private JTextField outputField;

    private byte[] fileInputBytes = null; // przechowuje bajty z pliku (binaria)

    public DESXGUI() {
        setTitle("DESX Szyfrowanie/Deszyfrowanie");
        setSize(700, 350);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new GridLayout(7, 2, 5, 5));

        inputField = new JTextField();
        key1Field = new JTextField();
        key2Field = new JTextField();
        key3Field = new JTextField();
        outputField = new JTextField();
        outputField.setEditable(false);

        JButton encryptButton = new JButton("Szyfruj");
        JButton decryptButton = new JButton("Deszyfruj");
        JButton loadFileButton = new JButton("Wczytaj z pliku");
        JButton saveFileButton = new JButton("Zapisz wynik do pliku");

        add(new JLabel("Tekst (dowolna długość) lub HEX do deszyfrowania:"));
        add(inputField);
        add(new JLabel("Klucz K1 (HEX lub liczba):"));
        add(key1Field);
        add(new JLabel("Klucz K2 (HEX lub liczba):"));
        add(key2Field);
        add(new JLabel("Klucz K3 (HEX lub liczba):"));
        add(key3Field);
        add(encryptButton);
        add(decryptButton);
        add(loadFileButton);
        add(saveFileButton);
        add(new JLabel("Wynik (HEX / Tekst):"));
        add(outputField);

        // --- Szyfrowanie ---
        encryptButton.addActionListener(e -> {
            try {
                fileInputBytes = null; // reset, jeśli wcześniej był plik
                byte[] paddedInput = pad(inputField.getText().getBytes("UTF-8"));

                long k1 = parseKey(key1Field.getText());
                long k2 = parseKey(key2Field.getText());
                long k3 = parseKey(key3Field.getText());

                ByteArrayOutputStream output = new ByteArrayOutputStream();
                for (int i = 0; i < paddedInput.length; i += 8) {
                    long block = bytesToLong(paddedInput, i);
                    long encrypted = DESX.encryptDESX(block, k1, k2, k3);
                    output.write(longToBytes(encrypted));
                }

                outputField.setText(bytesToHex(output.toByteArray()));

            } catch (Exception ex) {
                showError("Błąd szyfrowania: " + ex.getMessage());
            }
        });

        // --- Deszyfrowanie ---
        decryptButton.addActionListener(e -> {
            try {
                byte[] cipherBytes;

                if (fileInputBytes != null) {
                    cipherBytes = fileInputBytes;
                    if (cipherBytes.length % 8 != 0) {
                        showError("Długość danych binarnych nie jest wielokrotnością 8 bajtów.");
                        return;
                    }
                } else {
                    String hexString = inputField.getText().replaceAll("[^0-9A-Fa-f]", "");
                    if (hexString.length() == 0 || hexString.length() % 16 != 0) {
                        showError("Błąd: brak danych lub nieprawidłowy format HEX (musi być wielokrotność 16 znaków).");
                        return;
                    }
                    cipherBytes = new byte[hexString.length() / 2];
                    for (int i = 0; i < cipherBytes.length; i++) {
                        cipherBytes[i] = (byte) Integer.parseInt(hexString.substring(2 * i, 2 * i + 2), 16);
                    }
                }

                long k1 = parseKey(key1Field.getText());
                long k2 = parseKey(key2Field.getText());
                long k3 = parseKey(key3Field.getText());

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                for (int i = 0; i < cipherBytes.length; i += 8) {
                    long cipherBlock = bytesToLong(cipherBytes, i);
                    long decrypted = DESX.decryptDESX(cipherBlock, k1, k2, k3);
                    baos.write(longToBytes(decrypted));
                }

                byte[] unpadded = unpad(baos.toByteArray());
                outputField.setText(new String(unpadded, "UTF-8"));
                fileInputBytes = null; // reset po użyciu

            } catch (Exception ex) {
                showError("Błąd deszyfrowania: " + ex.getMessage());
            }
        });

        // --- Wczytaj z pliku ---
        loadFileButton.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                try {
                    fileInputBytes = Files.readAllBytes(chooser.getSelectedFile().toPath());
                    String asString = new String(fileInputBytes, "UTF-8").trim();

                    if (asString.matches("(?i)^[0-9a-f\\s]+$") && asString.length() % 16 == 0) {
                        inputField.setText(asString.replaceAll("\\s+", ""));
                        fileInputBytes = null; // nie potrzebujemy bajtów, to czysty HEX
                    } else {
                        inputField.setText("[Plik binarny wczytany – gotowy do deszyfrowania]");
                    }

                } catch (IOException ex) {
                    showError("Nie udało się odczytać pliku.");
                }
            }
        });

        // --- Zapisz do pliku ---
        saveFileButton.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                try {
                    byte[] data;
                    String outputText = outputField.getText();
                    if (outputText.matches("[0-9A-Fa-f ]+")) {
                        String hexString = outputText.replaceAll("[^0-9A-Fa-f]", "");
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        for (int i = 0; i < hexString.length(); i += 2) {
                            baos.write((byte) Integer.parseInt(hexString.substring(i, i + 2), 16));
                        }
                        data = baos.toByteArray();
                    } else {
                        data = outputText.getBytes("UTF-8");
                    }
                    Files.write(chooser.getSelectedFile().toPath(), data);
                } catch (IOException ex) {
                    showError("Nie udało się zapisać pliku.");
                }
            }
        });

        setVisible(true);
    }

    // --- Pomocnicze metody ---

    private byte[] pad(byte[] input) {
        int paddingLength = 8 - (input.length % 8);
        byte[] padded = new byte[input.length + paddingLength];
        System.arraycopy(input, 0, padded, 0, input.length);
        for (int i = input.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLength;
        }
        return padded;
    }

    private byte[] unpad(byte[] input) {
        int padValue = input[input.length - 1] & 0xFF;
        if (padValue < 1 || padValue > 8) return input;
        for (int i = input.length - padValue; i < input.length; i++) {
            if ((input[i] & 0xFF) != padValue) return input;
        }
        byte[] unpadded = new byte[input.length - padValue];
        System.arraycopy(input, 0, unpadded, 0, unpadded.length);
        return unpadded;
    }

    private long bytesToLong(byte[] data, int offset) {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result |= ((long) data[offset + i] & 0xFF) << (56 - i * 8);
        }
        return result;
    }

    private byte[] longToBytes(long value) {
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) ((value >> (56 - i * 8)) & 0xFF);
        }
        return bytes;
    }

    private long parseKey(String keyText) {
        keyText = keyText.trim();
        if (keyText.startsWith("0x") || keyText.matches("^[0-9a-fA-F]+$")) {
            if (keyText.replace("0x", "").length() > 16) {
                throw new IllegalArgumentException("Klucz HEX nie może mieć więcej niż 16 znaków (64 bity)");
            }
            return Long.parseUnsignedLong(keyText.replace("0x", ""), 16);
        } else {
            return Long.parseLong(keyText);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private void showError(String msg) {
        JOptionPane.showMessageDialog(this, msg);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new DESXGUI());
    }
}
