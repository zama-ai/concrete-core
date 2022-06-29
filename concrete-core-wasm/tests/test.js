const crypto = require('crypto');
const test = require('node:test');
const assert = require('node:assert').strict;
const {DefaultEngine, JsFunctionSeeder, LweDimension, Variance} = require("../pkg");

function seed() {
    const seed = new Uint8Array(16);
    crypto.getRandomValues(seed);
    return seed;
}


test('create_cleartext_f64', (t) => {
    let seeder = new JsFunctionSeeder(seed);
    let eng = new DefaultEngine(seeder);
    let val = 3.
    let cleartext = eng.create_cleartext_f64(val);
    let raw = eng.retrieve_cleartext_f64(cleartext);
    assert.strictEqual(val, raw);
});

test('create_cleartext_vector_f64', (t) => {
    let seeder = new JsFunctionSeeder(seed);
    let eng = new DefaultEngine(seeder);
    let val = new Float64Array([3.,2.,5.])
    let cleartext_vector = eng.create_cleartext_vector_f64(val);
    let raw = eng.retrieve_cleartext_vector_f64(cleartext_vector);
    assert.deepEqual(val, raw);
});

test('example_hackaton', (t) => {
    const SHIFT = 64 - (6+1);
    const LWE_DIM = new LweDimension(512);
    const NOISE = new Variance(Math.pow(2, -11));

    let seeder = new JsFunctionSeeder(seed);
    let eng = new DefaultEngine(seeder);
    let raw_plaintext_vector = new BigUint64Array([BigInt(3<<SHIFT), BigInt(2<<SHIFT), BigInt(5<<SHIFT)]);
    let plaintext_vector = eng.create_plaintext_vector_64(raw_plaintext_vector);
    let lwe_secret_key = eng.create_lwe_secret_key_64(LWE_DIM);
    let lwe_ciphertext_vector = eng.encrypt_lwe_ciphertext_vector_64(lwe_secret_key,plaintext_vector,NOISE);
    let raw_lwe_ciphertext_vector = eng.consume_retrieve_lwe_ciphertext_vector_64(lwe_ciphertext_vector);

    // On server, do your things.
    let response_raw_lwe_ciphertext_vector = raw_lwe_ciphertext_vector;
    // Now send back the response.

    let response_lwe_ciphertext_vector = eng.create_lwe_ciphertext_vector_64(response_raw_lwe_ciphertext_vector, LWE_DIM);
    let response_plaintext_vector = eng.decrypt_lwe_ciphertext_vector_64(lwe_secret_key, response_lwe_ciphertext_vector);
    let response_raw_plaintext_vector = eng.retrieve_plaintext_vector_64(response_plaintext_vector);

    console.log(response_raw_plaintext_vector);
})