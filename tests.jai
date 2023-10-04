main :: () {
    test_pbkdf2();
    test_unseal();
}

test_pbkdf2 :: () {
    test_pbkdf2(pbkdf2_sha256, "secret", "1234567890123456", "8b5014a03dad37ad56cd551532b28a79fdfe067dcd1779bb05ed851a15fbb056");
    test_pbkdf2(pbkdf2_sha1,   "secret", "1234567890123456", "c3c6a532365941200eaf0f6381f1665b4f1fd915b5c0d5c5433041a9ce5f72cb");
}

test_pbkdf2 :: (pbkdf2_fn: $T, secret: string, salt: string, expected_result: string) {
    success, result := pbkdf2_fn(secret, salt, 1, 32);
    assert(success);
    builder: String_Builder;
    for i: 0..result.count - 1 {
        print_to_builder(*builder, "%", formatInt(result[i], minimum_digits = 2, base = 16));
    }

    pbkdf2_hex := builder_to_string(*builder);
    log("pbkdf2_hex:\n%\n%", pbkdf2_hex, expected_result);
    assert(pbkdf2_hex == expected_result);
}

test_unseal :: () {
    test_unseal("Fe26.2**f6c6a46a7ea261d16d1db3b2d4c645db76e27d2411d603ce501d7d15adfb5f72*ldgU1B7d8FFrqO9N7c9qXA*hPDBhiOC3ePSu0WTUsjC_WlDtPBN_8L5yNhag2erVJPfdnVV-RYzwFXRDXXvjeSaQqltCF-di0aDAhux0VEfHUCEivx85KdmnjLOTMjdmpKDjfpDvyE6hj_pCr6-NYqY**d88f2ff8caf910f96cd3e8f72bf544b232b5ad0d4300a01a17e4a2c355a68143*tlMEkj3TzrV2Xy1URWjdYZKWRlqiEF4VRoWV9rWNQ1s", "devdevdevdevdevdevdevdevdevdevdevdev_api", "{\"sid\":\"b847220c-c4c5-4679-b598-4572ea2140b4\",\"date\":\"2023-09-25T08:27:38.747Z\"}");
}

test_unseal :: (payload: string, secret: string, expected: string) {
    options: Iron_Options;
    success, result := unseal(payload, secret, options);
    assert(success);

    log("Result: %", result);
    assert(result == expected);
}

#import "Basic";

#import,file "module.jai";


