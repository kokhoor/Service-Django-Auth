/*
 * Copyright 2021 SolutionX Software Sdn Bhd &lt;info@solutionx.com.my&gt;.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package my.com.solutionx.simplyscript_module.django_auth;

import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 *
 * @author SolutionX Software Sdn Bhd &lt;info@solutionx.com.my&gt;
 * 
 * Derived from: https://gist.github.com/lukaszb/1af1bd4233326e37a8a0
 * by: Lukasz Balcerzak
 */
public class PBKDF2WithHmacSHA256Hasher implements Hasher {
    final Integer DEFAULT_ITERATIONS = 260000;;
    final String ALGORITHM = "pbkdf2_sha256";
    final int SALT_ENTROPY = 128;

    public PBKDF2WithHmacSHA256Hasher() {
    }

    public String encode(final String password) {
        int char_count = (int)(Math.ceil(SALT_ENTROPY / Math.log(PasswordEncoderDecoder.RANDOM_STRING_CHARS.length()) / Math.log(2)));
        String salt = PasswordEncoderDecoder.generateRandomString(char_count);
        return encode(password, salt, DEFAULT_ITERATIONS);
    }

    public String encode(final String password, final String salt, final int iterations) {
        // returns hashed password, along with algorithm, number of iterations and salt
        String hash = getEncodedHash(password, salt, iterations);
        return String.format("%s$%d$%s$%s", ALGORITHM, iterations, salt, hash);
    }

    public boolean verifyPassword(final String password, final String hashedPassword) {
        // hashedPassword consist of: ALGORITHM, ITERATIONS_NUMBER, SALT and
        // HASH; parts are joined with dollar character ("$")
        String[] parts = hashedPassword.split("\\$");
        if (parts.length != 4) {
            // wrong hash format
            return false;
        }
        if (parts[0] == null || !parts[0].equalsIgnoreCase(ALGORITHM)) {
            // wrong type
            return false;
        }

        Integer iterations = Integer.parseInt(parts[1]);
        String salt = parts[2];
        String hash = encode(password, salt, iterations);

        return hash.equals(hashedPassword);
    }

    String getEncodedHash(final String password, final String salt, final int iterations) {
        // Returns only the last part of whole encoded password
        SecretKeyFactory keyFactory = null;
        try {
            keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Could NOT retrieve PBKDF2WithHmacSHA256 algorithm");
            return null;
        }
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(Charset.forName("UTF-8")), iterations, 256);
        SecretKey secret = null;
        try {
            secret = keyFactory.generateSecret(keySpec);
        } catch (InvalidKeySpecException e) {
            System.out.println("Could NOT generate secret key");
            return null;
        }

        byte[] rawHash = secret.getEncoded();
        byte[] hashBase64 = Base64.getEncoder().encode(rawHash);

        return new String(hashBase64);
    }  
}
