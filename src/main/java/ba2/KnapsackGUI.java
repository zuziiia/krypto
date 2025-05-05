package ba2;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class KnapsackGUI extends Application {

    private TextField messageField;
    private TextArea privateKeyArea;
    private TextArea publicKeyArea;
    private TextField outputField;
    private CheckBox useGeneratedKeyCheckBox;

    private GeneratedKey generatedKey;
    private Algorithm algorithm;
    private byte[] fileInputBytes = null;
    private byte[] decryptedBinaryOutput = null;

    private BigInteger mValue;
    private BigInteger nValue;

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Algorytm Plecakowy - Kryptografia");
        algorithm = new Algorithm();

        generatedKey = new GeneratedKey();
        mValue = generatedKey.getM();
        nValue = generatedKey.getN();

        BorderPane root = new BorderPane();
        root.setPadding(new Insets(10));

        GridPane mainGrid = new GridPane();
        mainGrid.setHgap(10);
        mainGrid.setVgap(10);
        mainGrid.setPadding(new Insets(10));

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

        Button generateKeyButton = new Button("Generuj klucz");
        Button generateMNButton = new Button("Generuj m i n");
        Button generatePublicKeyButton = new Button("Generuj klucz publiczny");
        Button encryptButton = new Button("Szyfruj");
        Button decryptButton = new Button("Deszyfruj");
        Button loadFileButton = new Button("Wczytaj z pliku");
        Button saveFileButton = new Button("Zapisz wynik do pliku");

        int row = 0;
        mainGrid.add(new Label("Wiadomość (binarna lub tekst):"), 0, row);
        mainGrid.add(messageField, 1, row++);

        mainGrid.add(new Label("Klucz prywatny (liczby oddzielone przecinkami):"), 0, row);
        mainGrid.add(privateKeyArea, 1, row++);

        mainGrid.add(new Label("Klucz publiczny:"), 0, row);
        mainGrid.add(publicKeyArea, 1, row++);

        mainGrid.add(new Label("Wynik:"), 0, row);
        mainGrid.add(outputField, 1, row++);

        mainGrid.add(useGeneratedKeyCheckBox, 0, row);
        mainGrid.add(generateKeyButton, 1, row++);

        HBox controlBox = new HBox(10);
        controlBox.getChildren().addAll(generateMNButton, generatePublicKeyButton);
        mainGrid.add(controlBox, 1, row);

        ColumnConstraints col1 = new ColumnConstraints();
        col1.setPercentWidth(30);
        ColumnConstraints col2 = new ColumnConstraints();
        col2.setPercentWidth(70);
        mainGrid.getColumnConstraints().addAll(col1, col2);

        HBox buttonBox = new HBox(10);
        buttonBox.setAlignment(Pos.CENTER);
        buttonBox.setPadding(new Insets(10));
        buttonBox.getChildren().addAll(encryptButton, decryptButton, loadFileButton, saveFileButton);

        root.setCenter(mainGrid);
        root.setBottom(buttonBox);

        generateKeyButton.setOnAction(e -> {
            try {
                generatedKey = new GeneratedKey();
                updateKeyFields();
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
                mValue = mnValues[0];
                nValue = mnValues[1];
                showInfo("Wartości m i n zostały wygenerowane.");
            } catch (Exception ex) {
                showError("Błąd generowania wartości m i n: " + ex.getMessage());
            }
        });

        generatePublicKeyButton.setOnAction(e -> {
            try {
                BigInteger[] privateKey = parsePrivateKey(privateKeyArea.getText());
                if (mValue == null || nValue == null) {
                    showError("Najpierw wygeneruj wartości m i n!");
                    return;
                }
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
                BigInteger[] publicKey = algorithm.generatePublicKey(privateKey, mValue, nValue);
                StringBuilder publicKeyBuilder = new StringBuilder();
                for (BigInteger value : publicKey) {
                    publicKeyBuilder.append(value).append(", ");
                }
                if (publicKeyBuilder.length() > 2) {
                    publicKeyBuilder.setLength(publicKeyBuilder.length() - 2);
                }
                publicKeyArea.setText(publicKeyBuilder.toString());
                showInfo("Klucz publiczny został wygenerowany pomyślnie.");
            } catch (Exception ex) {
                showError("Błąd generowania klucza publicznego: " + ex.getMessage());
            }
        });

        encryptButton.setOnAction(e -> {
            try {
                // Obsługa pliku
                if (fileInputBytes != null) {
                    List<BigInteger> encryptedBlocks = new ArrayList<>();
                    for (byte b : fileInputBytes) {
                        int[] bits = new int[8];
                        for (int i = 0; i < 8; i++) {
                            bits[i] = (b >> (7 - i)) & 1;
                        }
                        BigInteger encrypted = generatedKey.encrypt(bits);
                        encryptedBlocks.add(encrypted);
                    }

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ObjectOutputStream oos = new ObjectOutputStream(baos);
                    oos.writeObject(encryptedBlocks);
                    oos.close();
                    decryptedBinaryOutput = baos.toByteArray();
                    outputField.setText("Zaszyfrowano plik (" + encryptedBlocks.size() + " bloków)");

                } else {
                    // Obsługa wiadomości tekstowej
                    String message = messageField.getText();
                    if (message.isEmpty()) {
                        showError("Pole wiadomości jest puste!");
                        return;
                    }

                    byte[] textBytes = message.getBytes();
                    List<BigInteger> encrypted = new ArrayList<>();
                    for (byte b : textBytes) {
                        int[] bits = new int[8];
                        for (int i = 0; i < 8; i++) {
                            bits[i] = (b >> (7 - i)) & 1;
                        }
                        encrypted.add(generatedKey.encrypt(bits));
                    }

                    // Pokaż w polu wynikowym
                    outputField.setText(encrypted.stream()
                            .map(BigInteger::toString)
                            .reduce((a, b) -> a + " " + b)
                            .orElse(""));

                    // Zapisz jako bajty do ewentualnego pliku
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ObjectOutputStream oos = new ObjectOutputStream(baos);
                    oos.writeObject(encrypted);
                    oos.close();
                    decryptedBinaryOutput = baos.toByteArray();
                }

            } catch (Exception ex) {
                showError("Błąd szyfrowania: " + ex.getMessage());
            }
        });

        decryptButton.setOnAction(e -> {
            try {
                // Deszyfrowanie pliku
                if (fileInputBytes != null) {
                    ByteArrayInputStream bais = new ByteArrayInputStream(fileInputBytes);
                    ObjectInputStream ois = new ObjectInputStream(bais);
                    List<BigInteger> encryptedBlocks = (List<BigInteger>) ois.readObject();
                    ois.close();

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    for (BigInteger encrypted : encryptedBlocks) {
                        int[] bits = generatedKey.decrypt(encrypted);
                        int value = 0;
                        for (int i = 0; i < 8; i++) {
                            value = (value << 1) | bits[i];
                        }
                        baos.write((byte) value);
                    }

                    decryptedBinaryOutput = baos.toByteArray();
                    outputField.setText("Odszyfrowano plik: " + decryptedBinaryOutput.length + " bajtów");

                } else {
                    // Deszyfrowanie tekstu z pola
                    String input = messageField.getText();
                    if (input.isEmpty()) {
                        showError("Pole wiadomości jest puste!");
                        return;
                    }

                    String[] tokens = input.trim().split("\\s+");
                    List<BigInteger> encrypted = new ArrayList<>();
                    for (String token : tokens) {
                        encrypted.add(new BigInteger(token));
                    }

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    for (BigInteger enc : encrypted) {
                        int[] bits = generatedKey.decrypt(enc);
                        int value = 0;
                        for (int i = 0; i < 8; i++) {
                            value = (value << 1) | bits[i];
                        }
                        baos.write((byte) value);
                    }

                    byte[] resultBytes = baos.toByteArray();
                    outputField.setText(new String(resultBytes));
                    decryptedBinaryOutput = resultBytes;
                }

            } catch (Exception ex) {
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
                    decryptedBinaryOutput = null;
                    showInfo("Wczytano plik: " + file.getName());
                } catch (IOException ex) {
                    showError("Błąd podczas wczytywania pliku: " + ex.getMessage());
                }
            }
        });

        saveFileButton.setOnAction(e -> {
            if (decryptedBinaryOutput == null || decryptedBinaryOutput.length == 0) {
                showError("Brak danych do zapisania!");
                return;
            }

            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Zapisz plik");
            File file = fileChooser.showSaveDialog(primaryStage);
            if (file != null) {
                try (FileOutputStream fos = new FileOutputStream(file)) {
                    fos.write(decryptedBinaryOutput);
                    showInfo("Zapisano plik: " + file.getAbsolutePath());
                } catch (IOException ex) {
                    showError("Błąd podczas zapisu pliku: " + ex.getMessage());
                }
            }
        });

        primaryStage.setScene(new Scene(root, 800, 500));
        primaryStage.show();
    }

    private void updateKeyFields() {
        if (generatedKey != null) {
            StringBuilder privateKeyBuilder = new StringBuilder();
            for (BigInteger value : generatedKey.getPrivateKey()) {
                privateKeyBuilder.append(value).append(", ");
            }
            if (privateKeyBuilder.length() > 2) {
                privateKeyBuilder.setLength(privateKeyBuilder.length() - 2);
            }
            privateKeyArea.setText(privateKeyBuilder.toString());

            StringBuilder publicKeyBuilder = new StringBuilder();
            for (BigInteger value : generatedKey.getPublicKey()) {
                publicKeyBuilder.append(value).append(", ");
            }
            if (publicKeyBuilder.length() > 2) {
                publicKeyBuilder.setLength(publicKeyBuilder.length() - 2);
            }
            publicKeyArea.setText(publicKeyBuilder.toString());
        }
    }

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

    private void showInfo(String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Informacja");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void showError(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Błąd");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
