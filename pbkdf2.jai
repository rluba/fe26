pbkdf2_sha1   :: #bake_arguments pbkdf2(digest = .SHA1,   hash_size = 20);
pbkdf2_sha256 :: #bake_arguments pbkdf2(digest = .SHA256, hash_size = 32);

// See https://datatracker.ietf.org/doc/html/rfc8018
pbkdf2 :: (password: string, salt: string, iterations: int, key_length: int, $digest: mbedtls_md_type_t, $hash_size: int) -> success: bool, [] u8 {
    if key_length > 0xffff_ffff * hash_size {
        log_error("pbkdf2 error: Invalid key length");
        return false, .[];
    }

    hmac_base: mbedtls_md_context_t;
    defer mbedtls_md_free(*hmac_base);
    success := setup_md_context(*hmac_base, digest, cast([] u8) password);
    if !success return false, .[];

    hmac_block: mbedtls_md_context_t;
    defer mbedtls_md_free(*hmac_block);
    success = setup_md_context(*hmac_block, digest, cast([] u8) password);
    if !success return false, .[];

    result := mbedtls_md_hmac_update(*hmac_base, salt.data, xx salt.count);
    if result != 0 return false, .[];

    key_data := alloc(key_length);

    l := key_length / hash_size;
    if key_length % hash_size l += 1;

    for i: 0..l-1 {
        U: [hash_size] u8;
        T: [hash_size] u8;
        iv := cast(u32) i + 1;
        #if !BIG_ENDIAN byte_swap_in_place(*iv);

        result = mbedtls_md_clone(*hmac_block, *hmac_base);
        if result != 0 return false, .[];
        result = mbedtls_md_hmac_update(*hmac_block, cast(*u8) *iv, size_of(type_of(iv)));
        if result != 0 return false, .[];
        result = mbedtls_md_hmac_finish(*hmac_block, U.data);
        if result != 0 return false, .[];

        memcpy(T.data, U.data, U.count);

        for j: 2..iterations {
            result = mbedtls_md_hmac_starts(*hmac_block, password.data, xx password.count);
            if result != 0 return false, .[];
            result = mbedtls_md_hmac_update(*hmac_block, U.data, U.count);
            if result != 0 return false, .[];
            result = mbedtls_md_hmac_finish(*hmac_block, U.data);
            if result != 0 return false, .[];

            for U {
                T[it_index] ^= it;
            }
        }

        clen := key_length - i * hash_size;
        if (clen > hash_size) {
            clen = hash_size;
        }
        memcpy(key_data + i * hash_size, T.data, clen);
    }

    key: [] u8;
    key.data = key_data;
    key.count = key_length;

    return true, key;
}

setup_md_context :: (ctx: *mbedtls_md_context_t, digest: mbedtls_md_type_t, key: [] u8) -> bool {
    mbedtls_md_init(ctx);
    info := mbedtls_md_info_from_type(digest);
    if info == null return false;
    result := mbedtls_md_setup(ctx, info, 1);
    if result != 0 return false;
    result = mbedtls_md_hmac_starts(ctx, key.data, xx key.count);
    if result != 0 return false;
    return true;
}


#scope_file

BIG_ENDIAN :: false;

#import "Basic";
#import "Bit_Operations";
#import "mbedtls";

