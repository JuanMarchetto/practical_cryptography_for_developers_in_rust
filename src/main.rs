use blake2::Blake2s256;
use hmac::{Hmac, Mac};
use ripemd::Ripemd160;
use sha2::{Digest, Sha224, Sha256};
use sha3::{Keccak384, Sha3_224, Sha3_256, Sha3_384};
use whirlpool::Whirlpool;
use ring;

fn main() {
    print!("\n***** HASH FUNCTIONS *****\n");
    let text = "hello";

    let sha256hash = Sha256::digest(text);
    println!("SHA-256:   {:x?}", sha256hash);

    let mut hasher_sha3_256 = Sha3_256::new();
    hasher_sha3_256.update(text);
    let sha3_256 = hasher_sha3_256.finalize();
    println!("SHA3-256:   {:x?}", sha3_256);

    let mut hasher_blake2s256 = Blake2s256::new();
    hasher_blake2s256.update(text);
    let blake2s256 = hasher_blake2s256.finalize();
    println!("BLAKE2s:   {:x?}", blake2s256);

    let mut hasher_ripemd160 = Ripemd160::new();
    hasher_ripemd160.update(text);
    let hash160 = hasher_ripemd160.finalize();
    println!("RIPEMD-160:   {:x?}", hash160);

    let mut hasher_sha224 = Sha224::new();
    hasher_sha224.update(text);
    let sha224 = hasher_sha224.finalize();
    println!("SHA-224:   {:x?}", sha224);

    let mut hasher_sha3_224 = Sha3_224::new();
    hasher_sha3_224.update(text);
    let sha3_224 = hasher_sha3_224.finalize();
    println!("SHA3-224:   {:x?}", sha3_224);

    let mut hasher_sha3_384 = Sha3_384::new();
    hasher_sha3_384.update(text);
    let sha3_384 = hasher_sha3_384.finalize();
    println!("SHA3-384:   {:x?}", sha3_384);

    let mut hasher_keccak384 = Keccak384::new();
    hasher_keccak384.update(text);
    let keccak384 = hasher_keccak384.finalize();
    println!("Keccak384:   {:x?}", keccak384);

    let mut hasher_whirlpool = Whirlpool::new();
    hasher_whirlpool.update(text);
    let whirlpool = hasher_whirlpool.finalize();
    println!("Whirlpool:   {:x?}", whirlpool);

   println!("\n***** HMAC *****\n");
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(b"12345").expect("HMAC can take key of any size");
    mac.update(b"sample message");
    let result = mac.finalize();
    print!("HMAC SHA-256: {:x?}", result.into_bytes());

    let message = "hello";
    let key = "cryptography";
    let key_value = ring::hmac::Key::new(ring::hmac::HMAC_SHA384, key.as_bytes());
    let mut context = ring::hmac::Context::with_key(&key_value);
    context.update(message.as_bytes());
    let tag = context.sign();
    print!("\nHMAC SHA-256: {:x?}", tag.as_ref());

    let new_key = "again";
    let new_key_value = ring::hmac::Key::new(ring::hmac::HMAC_SHA384, new_key.as_bytes());
    let mut new_context = ring::hmac::Context::with_key(&new_key_value);
    new_context.update(message.as_bytes());
    let new_tag = new_context.sign();
    print!("\nHMAC SHA-256: {:x?}", new_tag.as_ref());
}
