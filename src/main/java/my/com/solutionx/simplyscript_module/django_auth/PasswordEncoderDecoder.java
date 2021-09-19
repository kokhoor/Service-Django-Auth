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

import java.util.Random;

/**
 *
 * @author SolutionX Software Sdn Bhd &lt;info@solutionx.com.my&gt;
 */
public class PasswordEncoderDecoder {
    static final String  UNUSABLE_PASSWORD_PREFIX = "!";
    static final int UNUSABLE_PASSWORD_SUFFIX_LENGTH = 40;
    static final String RANDOM_STRING_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    public static String encode(final String password) {
        if (password == null || password.length() == 0) {
            return UNUSABLE_PASSWORD_PREFIX + generateRandomString(UNUSABLE_PASSWORD_SUFFIX_LENGTH);
        }
        return encode(password, null);
    }

    public static String encode(final String password, final String hash) {
        Hasher hasher = null;
        if (hash == null || hash.equals("") || hash.equals("pbkdf2_sha256")) {
            hasher = new PBKDF2WithHmacSHA256Hasher();
        } else if (hash.equals("pbkdf2_sha1")) {
            hasher = new PBKDF2WithHmacSHA1Hasher();            
        }
        if (hasher != null)
            return hasher.encode(password);
        return null;
    }

    public static boolean verifyPassword(final String password, final String hashedPassword) {
        String[] parts = hashedPassword.split("\\$");
        if (parts.length != 4) {
            return false;
        }
        if (parts[0] == null) {
            return false;
        }
        Hasher hasher = null;

        if (parts[0].equalsIgnoreCase("pbkdf2_sha256")) {
            hasher = new PBKDF2WithHmacSHA256Hasher();
        } else if (parts[0].equalsIgnoreCase("pbkdf2_sha1")) {
            hasher = new PBKDF2WithHmacSHA1Hasher();
        }
        if (hasher == null) {
            return false;
        }
        return hasher.verifyPassword(password, hashedPassword);            
    }

    static String generateRandomString(int len) {
        Random random = new Random();
        StringBuilder buffer = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            int r = random.nextInt(RANDOM_STRING_CHARS.length());
            buffer.append(RANDOM_STRING_CHARS.charAt(r));
        }
        return buffer.toString();
    }
}
