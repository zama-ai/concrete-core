const crypto = require('crypto');
const test = require('node:test');
const assert = require('node:assert').strict;
const {DefaultEngine, JsFunctionSeeder} = require("../pkg");

function seed() {
    return crypto.randomBytes(16);
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

