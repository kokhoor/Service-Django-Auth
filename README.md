# SimplyScript Service: Django Auth

### This module is responsible to encode and verify django auth password using Java.

__Usage:__

1. Encode a password using default pbkdf2_sha256:

    `my.com.solutionx.simplyscript_module.django_auth.PasswordEncoderDecoder.encode(password);`

    Where:

    - password is a string containing password to encode<br><br>

2. Encode a password using selected hash:

   `my.com.solutionx.simplyscript_module.django_auth.PasswordEncoderDecoder.encode(password, hash);`

   Where:

     - password is a string containing password to encode
     - hash is a string containing hash to use. Currently supported hashers are (pbkdf2_sha256 and pbkdf2_sha1)<br><br>

3. Verify that a password is similar to an encoded password:

    `my.com.solutionx.simplyscript_module.django_auth.PasswordEncoderDecoder.verifyPassword(password, hashed_password);`

    Where:

     - password is a string containing password to be verified
     - hashed_password is a string containing hashed password to be verified against
