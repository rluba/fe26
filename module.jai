MAC_FORMAT_VERSION :: 2; // Prevent comparison of mac values generated with different normalized string formats
MAC_PREFIX         :: #run sprint("Fe26.%", MAC_FORMAT_VERSION);

Algorithm :: enum {
    AES_256_CBC;
    SHA256;
}

Algorithm_Options :: struct {
    saltBits            := 256;
    algorithm:          Algorithm;
    iterations          := 1;
    min_password_length := 32;
}

Iron_Options :: struct {
    encryption:          Algorithm_Options;
    encryption.algorithm = .AES_256_CBC;

    integrity:           Algorithm_Options;
    integrity.algorithm  = .SHA256;

    ttl_ms               := 0;  // Milliseconds, 0 means forever
    timestamp_skew_sec   := 60; // Seconds of permitted clock skew for incoming expirations
    localtime_offset_ms  := 0;  // Local clock time offset express in a number of milliseconds (positive or negative)
}

unseal :: (sealed: string, password: string, options: Iron_Options) -> success: bool, result: string {
    assert(password != "", "Missing password");
    now_ms := to_milliseconds(current_time_consensus()) + options.localtime_offset_ms;

    parts := split(sealed, cast(u8) #char "*");
    if parts.count != 8 {
        log_error("Unseal error: Incorrect number of sealed components");
        return false, "";
    }

    mac_prefix        := parts[0];
    password_id       := parts[1];
    encryption_salt   := parts[2];
    encryption_iv_b64 := parts[3];
    encrypted_b64     := parts[4];
    expiration_string := parts[5];
    hmac_salt         := parts[6];
    hmac              := parts[7];
    mac_base_string:  string;
    mac_base_string.data = parts[0].data;
    mac_base_string.count = parts[6].data - parts[0].data - 1;

    if mac_prefix != MAC_PREFIX {
        log_error("Unseal error: Wrong mac prefix");
        return false, "";
    }

    if expiration_string {
        expiration, success, remainder := string_to_int(expiration_string);
        if !success || remainder {
            log_error("Unseal error: Invalid expiration");
            return false, "";
        }

        if expiration <= (now_ms - (options.timestamp_skew_sec * 1000)) {
            log_error("Unseal error: Expired seal");
            return false, "";
        }
    }

    // Check hmac
    mac_options := options.integrity;
    success, computed_hmac := hmac_with_password(mac_base_string, password, hmac_salt, mac_options);
    if !time_safe_equal(computed_hmac, hmac) {
        log_error("Unseal error: Invalid hmac value");
        return false, "";
    }

    // Decrypt
    encrypted_data, success= := base64_decode(encrypted_b64, table = BASE64URL_DECODER_TABLE);
    if !success {
        log_error("Unseal error: Invalid base64 data: \"%\"", encrypted_b64);
        return false, "";
    }

    encryption_iv, success= := base64_decode(encryption_iv_b64, table = BASE64URL_DECODER_TABLE);
    if !success {
        log_error("Unseal error: Invalid base64 IV");
        return false, "";
    }

    success=, decrypted := decrypt(cast([] u8) encrypted_data, password, encryption_salt, cast([] u8) encryption_iv, options.encryption);

    return success, decrypted;
}

// encrypt :: (password, options, data) -> success: bool, result: string {
//     success, key := generate_key(password, salt, iv, options);
//     if !success return false, "";
//     defer free(key);
//     const cipher = Crypto.createCipheriv(options.algorithm, key.key, key.iv);
//     const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);

//     return { encrypted, key };
// }


decrypt :: (data: [] u8, password: string, salt: string, iv: [] u8, options: Algorithm_Options) -> success: bool, result: string {
    success, key := generate_key(password, salt, iv, options);
    if !success return false, "";
    defer array_free(key);

    assert(options.algorithm == .AES_256_CBC, "@Incomplete");
    if options.algorithm != .AES_256_CBC return false, "";

    BLOCK_SIZE :: 16;
    assert(data.count % BLOCK_SIZE == 0);
    assert(key.count == 32);

    assert(iv.count == BLOCK_SIZE);
    iv_copy: [BLOCK_SIZE] u8;
    memcpy(iv_copy.data, iv.data, iv.count);

    aes: mbedtls_aes_context;
    mbedtls_aes_init(*aes);
    defer mbedtls_aes_free(*aes);

    result := mbedtls_aes_setkey_dec(*aes, key.data, xx (key.count * 8));
    if result != 0 return false, "";

    output := NewArray(data.count, u8);
    result = mbedtls_aes_crypt_cbc(*aes, MBEDTLS_AES_DECRYPT, xx data.count, *iv_copy, data.data, output.data);
    if result != 0 {
        array_free(output);
        return false, "";
    }

    padding := output[data.count-1];
    if padding > 16 || padding > output.count {
        log_error("descrypt: Invalid padding: %", padding);
        array_free(output);
        return false, "";
    }
    output.count -= padding;

    output_string := cast(string) output;
    return true, output_string;
};

hmac_with_password :: (data: string, password: string, salt: string, options: Algorithm_Options) -> success: bool, hmac: string, salt: string {
    success, key, key_salt := generate_key(password, salt, .[], options);
    if !success return false, "", "";
    defer array_free(key);

    assert(options.algorithm == .SHA256, "@Incomplete");
    if options.algorithm != .SHA256 return false, "", "";

    hmac: [32] u8;
    hmac_context: mbedtls_md_context_t;
    defer mbedtls_md_free(*hmac_context);
    success = setup_md_context(*hmac_context, .SHA256, key);
    if !success return false, "", "";
    result := mbedtls_md_hmac_update(*hmac_context, data.data, xx data.count);
    if result != 0 return false, "", "";
    result = mbedtls_md_hmac_finish(*hmac_context, hmac.data);
    if result != 0 return false, "", "";

    result_b64 := base64_encode(cast(string) hmac, table = BASE64URL_ENCODER_TABLE, pad = false);
    return true, result_b64, key_salt;
}


generate_key :: (password: string, salt: string, iv: [] u8, options: Algorithm_Options) -> success: bool, key: [] u8, salt: string, iv: [] u8 {
    assert(password != "", "Missing password");
    if password.count < options.min_password_length {
        log_error("Password is too short");
        return false, .[], "", .[];
    }

    key_bits: int;
    iv_bits: int;
    if #complete options.algorithm == {
        case .AES_256_CBC;
            key_bits = 256;
            iv_bits = 128;
        case .SHA256;
            key_bits = 256;
    }

    // @Incomplete: generate salt if not provided
    assert(salt != "", "Missing salt");
    // let salt = options.salt;
    // if (!salt) {
    //     if (!options.saltBits) {
    //         throw new Boom.Boom('Missing salt and saltBits options');
    //     [] u8

    //     const randomSalt = Cryptiles.randomBits(options.saltBits);
    //     salt = randomSalt.toString('hex');
    // }

    // @Incomplete: generate iv if not provided
    assert(!iv_bits || iv.count > 0, "Missing iv");
    // if (options.iv) {
    //     result.iv = options.iv;
    // }
    // else if (iv_bits) {
    //     result.iv = Cryptiles.randomBits(iv_bits);
    // }

    success, derived_key := pbkdf2_sha1(password, salt, options.iterations, key_bits / 8);
    return success, derived_key, salt, iv;
}


#load "pbkdf2.jai";

#import "String";
#import "Base64";
