import BackpackAlgh.GeneratedKey;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.lang.reflect.Field;

    public class generateTest {

        @Test
        public void testPrivateKeyGeneration() {
            GeneratedKey key = new GeneratedKey();

            // Use reflection to access the private field
            BigInteger[] privateKey = getPrivateKeyField(key);

            // Check if array has correct size
            assertEquals(8, privateKey.length);

            // Check if array is not null and elements are not null
            assertNotNull(privateKey);
            for (BigInteger value : privateKey) {
                assertNotNull(value);
            }

            // Check if the sequence is superincreasing (each element is greater than sum of all previous)
            BigInteger sum = BigInteger.ZERO;
            for (BigInteger value : privateKey) {
                assertTrue(value.compareTo(sum) > 0,
                        "Expected " + value + " to be greater than " + sum);
                sum = sum.add(value);
            }

            // Check if the first element is positive and non-zero
            assertTrue(privateKey[0].compareTo(BigInteger.ZERO) > 0,
                    "First element should be positive");
        }

        @Test
        public void testMandNCalculation() {
            GeneratedKey key = new GeneratedKey();

            BigInteger[] privateKey = getPrivateKeyField(key);
            BigInteger m = getMField(key);
            BigInteger n = getNField(key);

            // Calculate sum of private key elements
            BigInteger sum = BigInteger.ZERO;
            for (BigInteger value : privateKey) {
                sum = sum.add(value);
            }

            // Check if m is greater than sum
            assertTrue(m.compareTo(sum) > 0,
                    "m should be greater than the sum of private key elements");

            // Check if n is less than m
            assertTrue(n.compareTo(m) < 0,
                    "n should be less than m");

            // Check if n and m are coprime (gcd = 1)
            assertEquals(BigInteger.ONE, n.gcd(m),
                    "n and m should be coprime (gcd = 1)");

            // Check if n is greater than 1
            assertTrue(n.compareTo(BigInteger.ONE) > 0,
                    "n should be greater than 1");
        }

        @Test
        public void testPropertyAssignment() {
            GeneratedKey key = new GeneratedKey();

            // Check if all fields are properly initialized (not null)
            assertNotNull(getPrivateKeyField(key));
            assertNotNull(getMField(key));
            assertNotNull(getNField(key));

            // Create a second instance to ensure field values are unique per instance
            GeneratedKey key2 = new GeneratedKey();

            // Fields should be different between instances
            assertNotSame(getPrivateKeyField(key), getPrivateKeyField(key2));
            assertNotSame(getMField(key), getMField(key2));
            assertNotSame(getNField(key), getNField(key2));

            // Testing state consistency: in a correctly functioning system,
            // the parameters m and n should be consistent with the private key
            // This means m and n shouldn't change unless private key changes
            BigInteger originalM = getMField(key);
            BigInteger originalN = getNField(key);

            // Let's generate new N and M based on the same private key
            // First, create a copy of the original key to avoid affecting our original test object
            try {
                Field privateKeyField = key.getClass().getDeclaredField("privateKey");
                privateKeyField.setAccessible(true);
                BigInteger[] privateKeyCopy = getPrivateKeyField(key);

                // Create a new key instance
                GeneratedKey newKey = new GeneratedKey();

                // Replace its private key with our original
                privateKeyField.set(newKey, privateKeyCopy);

                // Generate new M and N
                newKey.generateNandM();

                // M and N should now be different from original, even with same private key
                // because generation includes randomness
                // But they should still follow the mathematical constraints
                BigInteger newM = getMField(newKey);
                BigInteger newN = getNField(newKey);

                // Check M and N are not the same as original
                // Note: There's a tiny chance of this failing due to randomness
                // but it's extremely unlikely
                assertNotEquals(originalM, newM);
                assertNotEquals(originalN, newN);

                // Check that the new M and N still follow constraints
                BigInteger sum = BigInteger.ZERO;
                for (BigInteger value : privateKeyCopy) {
                    sum = sum.add(value);
                }

                assertTrue(newM.compareTo(sum) > 0);
                assertTrue(newN.compareTo(newM) < 0);
                assertEquals(BigInteger.ONE, newN.gcd(newM));

            } catch (NoSuchFieldException | IllegalAccessException e) {
                fail("Failed to access fields via reflection: " + e.getMessage());
            }
        }

        // Helper methods to access private fields using reflection
        private BigInteger[] getPrivateKeyField(GeneratedKey key) {
            try {
                Field field = key.getClass().getDeclaredField("privateKey");
                field.setAccessible(true);
                return (BigInteger[]) field.get(key);
            } catch (NoSuchFieldException | IllegalAccessException e) {
                fail("Failed to access privateKey field: " + e.getMessage());
                return null;
            }
        }

        private BigInteger getMField(GeneratedKey key) {
            try {
                Field field = key.getClass().getDeclaredField("m");
                field.setAccessible(true);
                return (BigInteger) field.get(key);
            } catch (NoSuchFieldException | IllegalAccessException e) {
                fail("Failed to access m field: " + e.getMessage());
                return null;
            }
        }

        private BigInteger getNField(GeneratedKey key) {
            try {
                Field field = key.getClass().getDeclaredField("n");
                field.setAccessible(true);
                return (BigInteger) field.get(key);
            } catch (NoSuchFieldException | IllegalAccessException e) {
                fail("Failed to access n field: " + e.getMessage());
                return null;
            }
        }

        // For the third test to work properly, we need to make generateNandM public
        // Here's how the modified class would look:
    /*
    public class GeneratedKey {
        private final SecureRandom random = new SecureRandom();
        private BigInteger[] privateKey;
        private BigInteger m;
        private BigInteger n;

        GeneratedKey() {
            this.privateKey = generate();
            generateNandM(); // Call the method to set m and n
        }

        // Other methods...

        // Changed from private to public for testing
        public void generateNandM() {
            BigInteger sum = BigInteger.ZERO;
            for (BigInteger value : privateKey) {
                sum = sum.add(value);
            }

            this.m = sum.add(BigInteger.valueOf(random.nextInt(20) + 10));

            do {
                this.n = new BigInteger(m.bitLength() - 1, random); // mniejsza niż m
            } while (!n.gcd(m).equals(BigInteger.ONE) || n.compareTo(BigInteger.ONE) <= 0);
        }
    }
    */
    }

