package ba2;


import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.Base64;

public class KnapsackGUIFX2 extends Application {

    private TextField messageField;
    private TextArea privateKeyArea;
    private TextArea publicKeyArea;
    private TextField outputField;
    private CheckBox useGeneratedKeyCheckBox;

    private GeneratedKey generatedKey;
    private Algorithm algorithm;
    private byte[] fileInputBytes = null;

    // Hidden fields for m and n values (not displayed but still used)
    private BigInteger mValue;
    private BigInteger nValue;

    @Override
    public void start(Stage primaryStage) {
        // Set title and initialize algorithm
        primaryStage.setTitle("Algorytm Plecakowy - Kryptografia");
        algorithm = new Algorithm();

        // Main layout
        BorderPane root = new BorderPane();
        root.setPadding(new Insets(10));

        // Create main control grid
        GridPane mainGrid = new GridPane();
        mainGrid.setHgap(10);
        mainGrid.setVgap(10);
        mainGrid.setPadding(new Insets(10));

        // Initialize components
        messageField = new TextField();
        privateKeyArea = new TextArea();
        privateKeyArea.setPrefRowCount(4);
        privateKeyArea.setWrapText(true);

        publicKeyArea = new TextArea();
        publicKeyArea.setPrefRowCount(4);
        publicKeyArea.setWrapText(true);
        publicKeyArea.setEditable(false);

        outputField = new TextField();
        outputField.setEditable(false);

        useGeneratedKeyCheckBox = new CheckBox("Użyj wygenerowanego klucza");
        useGeneratedKeyCheckBox.setSelected(true);

        // Create buttons
        Button generateKeyButton = new Button("Generuj klucz");
        Button generateMNButton = new Button("Generuj m i n");
        Button generatePublicKeyButton = new Button("Generuj klucz publiczny");
        Button encryptButton = new Button("Szyfruj");
        Button decryptButton = new Button("Deszyfruj");
        Button loadFileButton = new Button("Wczytaj z pliku");
        Button saveFileButton = new Button("Zapisz wynik do pliku");

        // Add components to grid
        int row = 0;
        mainGrid.add(new Label("Wiadomość (binarna lub tekst):"), 0, row);
        mainGrid.add(messageField, 1, row);
        row++;

        mainGrid.add(new Label("Klucz prywatny (liczby oddzielone przecinkami):"), 0, row);
        mainGrid.add(privateKeyArea, 1, row);
        row++;

        mainGrid.add(new Label("Klucz publiczny:"), 0, row);
        mainGrid.add(publicKeyArea, 1, row);
        row++;

        mainGrid.add(new Label("Wynik:"), 0, row);
        mainGrid.add(outputField, 1, row);
        row++;

        mainGrid.add(useGeneratedKeyCheckBox, 0, row);
        mainGrid.add(generateKeyButton, 1, row);
        row++;

        // Create a sub-panel for some buttons
        HBox controlBox = new HBox(10);
        controlBox.getChildren().addAll(generateMNButton, generatePublicKeyButton);
        mainGrid.add(controlBox, 1, row);

        // Set column constraints
        ColumnConstraints col1 = new ColumnConstraints();
        col1.setPercentWidth(30);
        ColumnConstraints col2 = new ColumnConstraints();
        col2.setPercentWidth(70);
        mainGrid.getColumnConstraints().addAll(col1, col2);

        // Create button panel
        HBox buttonBox = new HBox(10);
        buttonBox.setAlignment(Pos.CENTER);
        buttonBox.setPadding(new Insets(10));
        buttonBox.getChildren().addAll(encryptButton, decryptButton, loadFileButton, saveFileButton);

        // Add everything to root layout
        root.setCenter(mainGrid);
        root.setBottom(buttonBox);

        // Set up event handlers
        useGeneratedKeyCheckBox.setOnAction(e -> {
            boolean useGenerated = useGeneratedKeyCheckBox.isSelected();
            privateKeyArea.setEditable(!useGenerated);
            generateMNButton.setDisable(useGenerated);
            generatePublicKeyButton.setDisable(useGenerated);

            if (useGenerated && generatedKey != null) {
                updateKeyFields();
            }
        });

        generateKeyButton.setOnAction(e -> {
            try {
                generatedKey = new GeneratedKey();
                updateKeyFields();
                // Store m and n values
                mValue = generatedKey.getM();
                nValue = generatedKey.getN();
                showInfo("Klucz został wygenerowany pomyślnie.");
            } catch (Exception ex) {
                showError("Błąd generowania klucza: " + ex.getMessage());
            }
        });

        generateMNButton.setOnAction(e -> {
            try {
                BigInteger[] privateKey = parsePrivateKey(privateKeyArea.getText());
                BigInteger[] mnValues = algorithm.generateNandM(privateKey);

                // Store m and n values but don't display them
                mValue = mnValues[0];
                nValue = mnValues[1];

                showInfo("Wartości m i n zostały wygenerowane.");
            } catch (Exception ex) {
                showError("Błąd generowania wartości m i n: " + ex.getMessage());
            }
        });

        generatePublicKeyButton.setOnAction(e -> {
            try {
                // Sprawdź czy klucz prywatny jest poprawny
                BigInteger[] privateKey = parsePrivateKey(privateKeyArea.getText());

                // Upewnij się, że m i n zostały wygenerowane
                if (mValue == null || nValue == null) {
                    showError("Najpierw wygeneruj wartości m i n!");
                    return;
                }

                // Sprawdź warunki dla m i n
                BigInteger sum = BigInteger.ZERO;
                for (BigInteger value : privateKey) {
                    sum = sum.add(value);
                }

                if (mValue.compareTo(sum) <= 0) {
                    showError("Wartość m musi być większa niż suma elementów klucza prywatnego!");
                    return;
                }

                if (nValue.compareTo(mValue) >= 0 || nValue.compareTo(BigInteger.ONE) <= 0 || !nValue.gcd(mValue).equals(BigInteger.ONE)) {
                    showError("Wartość n musi być mniejsza od m, większa od 1 i względnie pierwsza z m!");
                    return;
                }

                // Generuj klucz publiczny
                BigInteger[] publicKey = algorithm.generatePublicKey(privateKey, mValue, nValue);

                // Wyświetl klucz publiczny
                StringBuilder publicKeyBuilder = new StringBuilder();
                for (BigInteger value : publicKey) {
                    publicKeyBuilder.append(value).append(", ");
                }
                if (publicKeyBuilder.length() > 2) {
                    publicKeyBuilder.setLength(publicKeyBuilder.length() - 2); // Usuń ostatnie ", "
                }
                publicKeyArea.setText(publicKeyBuilder.toString());

                showInfo("Klucz publiczny został wygenerowany pomyślnie.");
            } catch (Exception ex) {
                showError("Błąd generowania klucza publicznego: " + ex.getMessage());
            }
        });

        encryptButton.setOnAction(e -> {
            try {
                String message = messageField.getText().trim();
                if (message.isEmpty()) {
                    if (fileInputBytes == null) {
                        showError("Wprowadź wiadomość do zaszyfrowania.");
                        return;
                    }
                    message = Base64.getEncoder().encodeToString(fileInputBytes);
                }

                // Konwersja wiadomości na tablicę bitów
                int[] bits = convertToBits(message);

                BigInteger[] publicKey;

                if (useGeneratedKeyCheckBox.isSelected()) {
                    if (generatedKey == null) {
                        showError("Najpierw wygeneruj klucz.");
                        return;
                    }
                    publicKey = generatedKey.getPublicKey();
                } else {
                    // Użyj wprowadzonego klucza
                    publicKey = parsePublicKey(publicKeyArea.getText());
                    if (publicKey.length == 0) {
                        showError("Klucz publiczny jest pusty. Najpierw wygeneruj klucz publiczny.");
                        return;
                    }
                }

                // Sprawdź czy długość klucza = 8
                if (publicKey.length != 8) {
                    showError("Klucz publiczny musi mieć długość 8 elementów!");
                    return;
                }

                // Dzielenie na bloki po 8 bitów (długość klucza)
                StringBuilder resultBuilder = new StringBuilder();

                for (int i = 0; i < bits.length; i += 8) {
                    int[] block = new int[8];
                    // Inicjalizacja bloku zerami (padding)
                    for (int j = 0; j < 8; j++) {
                        block[j] = 0;
                    }

                    // Wypełnienie bloku dostępnymi bitami
                    for (int j = 0; j < 8 && i + j < bits.length; j++) {
                        block[j] = bits[i + j];
                    }

                    BigInteger encrypted;
                    if (useGeneratedKeyCheckBox.isSelected()) {
                        encrypted = generatedKey.encrypt(block);
                    } else {
                        encrypted = algorithm.encrypt(block, publicKey);
                    }

                    resultBuilder.append(encrypted.toString()).append(" ");
                }

                outputField.setText(resultBuilder.toString().trim());

            } catch (Exception ex) {
                ex.printStackTrace();
                showError("Błąd szyfrowania: " + ex.getMessage());
            }
        });

        decryptButton.setOnAction(e -> {
            try {
                String[] encryptedBlocks = messageField.getText().trim().split("\\s+");
                if (encryptedBlocks.length == 0 || encryptedBlocks[0].isEmpty()) {
                    showError("Wprowadź zaszyfrowaną wiadomość.");
                    return;
                }

                BigInteger[] privateKey;
                BigInteger m, n;

                if (useGeneratedKeyCheckBox.isSelected()) {
                    if (generatedKey == null) {
                        showError("Najpierw wygeneruj klucz.");
                        return;
                    }
                    privateKey = generatedKey.getPrivateKey();
                    m = generatedKey.getM();
                    n = generatedKey.getN();
                } else {
                    privateKey = parsePrivateKey(privateKeyArea.getText());

                    if (mValue == null || nValue == null) {
                        showError("Wartości m i n nie zostały ustawione. Wygeneruj je najpierw.");
                        return;
                    }

                    m = mValue;
                    n = nValue;
                }

                // Deszyfrowanie każdego bloku
                StringBuilder bitBuilder = new StringBuilder();

                for (String block : encryptedBlocks) {
                    if (block.isEmpty()) continue;

                    BigInteger encryptedValue = new BigInteger(block);
                    int[] decryptedBits;

                    if (useGeneratedKeyCheckBox.isSelected()) {
                        decryptedBits = generatedKey.decrypt(encryptedValue);
                    } else {
                        decryptedBits = algorithm.decrypt(encryptedValue, privateKey, m, n);
                    }

                    for (int bit : decryptedBits) {
                        bitBuilder.append(bit);
                    }
                }

                // Konwersja bitów z powrotem na tekst
                String result = convertFromBits(bitBuilder.toString());
                outputField.setText(result);

            } catch (Exception ex) {
                ex.printStackTrace();
                showError("Błąd deszyfrowania: " + ex.getMessage());
            }
        });

        loadFileButton.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Wczytaj plik");
            File file = fileChooser.showOpenDialog(primaryStage);

            if (file != null) {
                try {
                    fileInputBytes = Files.readAllBytes(file.toPath());
                    messageField.setText("[Plik wczytany - " + fileInputBytes.length + " bajtów]");
                } catch (IOException ex) {
                    showError("Nie udało się odczytać pliku: " + ex.getMessage());
                }
            }
        });

        saveFileButton.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Zapisz wynik");
            File file = fileChooser.showSaveDialog(primaryStage);

            if (file != null) {
                try {
                    String output = outputField.getText();
                    if (output.isEmpty()) {
                        showError("Brak danych do zapisania.");
                        return;
                    }

                    // Sprawdź czy wynik to ciąg liczb (zaszyfrowany) czy tekst (odszyfrowany)
                    if (output.matches("^[0-9\\s]+$")) {
                        // Zaszyfrowany - zapisz jako tekst
                        Files.write(file.toPath(), output.getBytes());
                    } else {
                        // Odszyfrowany - zapisz jako tekst lub bajty
                        Files.write(file.toPath(), output.getBytes());
                    }
                    showInfo("Plik został zapisany pomyślnie.");
                } catch (IOException ex) {
                    showError("Nie udało się zapisać pliku: " + ex.getMessage());
                }
            }
        });

        // Set initial state
        generateMNButton.setDisable(useGeneratedKeyCheckBox.isSelected());
        generatePublicKeyButton.setDisable(useGeneratedKeyCheckBox.isSelected());

        // Generate initial key
        generatedKey = new GeneratedKey();
        updateKeyFields();
        mValue = generatedKey.getM();
        nValue = generatedKey.getN();

        // Set up stage
        Scene scene = new Scene(root, 800, 500);  // Reduced height since we removed elements
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void updateKeyFields() {
        if (generatedKey != null) {
            // Aktualizacja klucza prywatnego
            StringBuilder privateKeyBuilder = new StringBuilder();
            for (BigInteger value : generatedKey.getPrivateKey()) {
                privateKeyBuilder.append(value).append(", ");
            }
            if (privateKeyBuilder.length() > 2) {
                privateKeyBuilder.setLength(privateKeyBuilder.length() - 2); // Usuń ostatnie ", "
            }
            privateKeyArea.setText(privateKeyBuilder.toString());

            // Aktualizacja klucza publicznego
            StringBuilder publicKeyBuilder = new StringBuilder();
            for (BigInteger value : generatedKey.getPublicKey()) {
                publicKeyBuilder.append(value).append(", ");
            }
            if (publicKeyBuilder.length() > 2) {
                publicKeyBuilder.setLength(publicKeyBuilder.length() - 2); // Usuń ostatnie ", "
            }
            publicKeyArea.setText(publicKeyBuilder.toString());

            // Aktualizacja ukrytych m i n
            mValue = generatedKey.getM();
            nValue = generatedKey.getN();
        }
    }

    // Konwersja tekstu na bity
    private int[] convertToBits(String text) {
        byte[] bytes = text.getBytes();
        int[] bits = new int[bytes.length * 8];

        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                bits[i * 8 + j] = (bytes[i] >> (7 - j)) & 1;
            }
        }

        return bits;
    }

    // Konwersja bitów na tekst
    private String convertFromBits(String bitString) {
        // Dopełnij do wielokrotności 8
        int padding = bitString.length() % 8;
        if (padding > 0) {
            padding = 8 - padding;
            StringBuilder paddedBits = new StringBuilder(bitString);
            for (int i = 0; i < padding; i++) {
                paddedBits.append("0");
            }
            bitString = paddedBits.toString();
        }

        if (bitString.isEmpty()) {
            return "";
        }

        byte[] bytes = new byte[bitString.length() / 8];

        for (int i = 0; i < bytes.length; i++) {
            String byteString = bitString.substring(i * 8, (i + 1) * 8);
            bytes[i] = (byte) Integer.parseInt(byteString, 2);
        }

        return new String(bytes);
    }

    // Parsowanie klucza prywatnego z tekstu
    private BigInteger[] parsePrivateKey(String keyText) {
        if (keyText == null || keyText.trim().isEmpty()) {
            throw new IllegalArgumentException("Klucz prywatny jest pusty!");
        }

        String[] parts = keyText.split(",");
        BigInteger[] key = new BigInteger[parts.length];

        for (int i = 0; i < parts.length; i++) {
            String part = parts[i].trim();
            if (part.isEmpty()) {
                throw new IllegalArgumentException("Nieprawidłowy format klucza - pusty element!");
            }
            key[i] = new BigInteger(part);
        }

        if (!algorithm.isSuperIncreasing(key)) {
            throw new IllegalArgumentException("Klucz prywatny nie jest ciągiem superrosnącym!");
        }

        return key;
    }

    // Parsowanie klucza publicznego z tekstu
    private BigInteger[] parsePublicKey(String keyText) {
        if (keyText == null || keyText.trim().isEmpty()) {
            return new BigInteger[0];
        }

        String[] parts = keyText.split(",");
        BigInteger[] key = new BigInteger[parts.length];

        for (int i = 0; i < parts.length; i++) {
            String part = parts[i].trim();
            if (part.isEmpty()) {
                continue;
            }
            key[i] = new BigInteger(part);
        }

        return key;
    }

    private void showError(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Błąd");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void showInfo(String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Informacja");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
