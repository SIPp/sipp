//! 3GPP TS 35.206 Milenage, the AKA functions f1 and f2-f5 SIPp's
//! AKAv1-MD5 needs.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

type Block = [u8; 16];

fn aes(k: &Block, input: &Block) -> Block {
    let mut b = (*input).into();
    Aes128::new(k.into()).encrypt_block(&mut b);
    b.into()
}

fn xor(a: &Block, b: &Block) -> Block {
    std::array::from_fn(|i| a[i] ^ b[i])
}

/// Rotates left by `bytes` bytes (r1-r5 are all whole bytes).
fn rot(a: &Block, bytes: usize) -> Block {
    std::array::from_fn(|i| a[(i + bytes) % 16])
}

/// OPc = OP xor E_K(OP).
fn opc(k: &Block, op: &Block) -> Block {
    xor(&aes(k, op), op)
}

/// f1: MAC-A, the network's authentication code.
pub fn f1(k: &Block, rand: &Block, sqn: &[u8; 6], amf: &[u8; 2], op: &Block) -> [u8; 8] {
    let opc = opc(k, op);
    let temp = aes(k, &xor(rand, &opc));
    let mut in1 = [0u8; 16];
    for half in 0..2 {
        in1[half * 8..half * 8 + 6].copy_from_slice(sqn);
        in1[half * 8 + 6..half * 8 + 8].copy_from_slice(amf);
    }
    // r1 = 64 bits, c1 = 0.
    let out = xor(&aes(k, &xor(&temp, &rot(&xor(&in1, &opc), 8))), &opc);
    out[..8].try_into().unwrap()
}

/// What f2-f5 give: RES, CK, IK and AK (CK and IK unused: SIPp only
/// computes them).
#[allow(dead_code)]
pub struct Vector {
    pub res: [u8; 8],
    pub ck: Block,
    pub ik: Block,
    pub ak: [u8; 6],
}

/// f2, f3, f4 and f5.
pub fn f2345(k: &Block, rand: &Block, op: &Block) -> Vector {
    let opc = opc(k, op);
    let temp = aes(k, &xor(rand, &opc));
    let out = |r: usize, c: u8| {
        let mut x = rot(&xor(&temp, &opc), r);
        x[15] ^= c;
        xor(&aes(k, &x), &opc)
    };
    // r2 = 0, r3 = 32, r4 = 64 bits; c2 = 1, c3 = 2, c4 = 4.
    let out2 = out(0, 1);
    Vector { res: out2[8..].try_into().unwrap(), ck: out(4, 2), ik: out(8, 4), ak: out2[..6].try_into().unwrap() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        std::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
    }

    /// TS 35.207, test sets 1 and 2.
    #[test]
    fn test_sets() {
        for (k, rand, sqn, amf, op, mac, res, ck, ik, ak) in [
            (
                "465b5ce8b199b49faa5f0a2ee238a6bc", "23553cbe9637a89d218ae64dae47bf35", "ff9bb4d0b607", "b9b9",
                "cdc202d5123e20f62b6d676ac72cb318", "4a9ffac354dfafb3", "a54211d5e3ba50bf",
                "b40ba9a3c58b2a05bbf0d987b21bf8cb", "f769bcd751044604127672711c6d3441", "aa689c648370",
            ),
            (
                "0396eb317b6d1c36f19c1c84cd6ffd16", "c00d603103dcee52c4478119494202e8", "fd8eef40df7d", "af17",
                "ff53bade17df5d4e793073ce9d7579fa", "5df5b31807e258b0", "d3a628ed988620f0",
                "58c433ff7a7082acd424220f2b67c556", "21a8c1f929702adb3e738488b9f5c5da", "c47783995f72",
            ),
        ] {
            let (k, rand, op) = (h::<16>(k), h::<16>(rand), h::<16>(op));
            assert_eq!(f1(&k, &rand, &h(sqn), &h(amf), &op), h::<8>(mac));
            let v = f2345(&k, &rand, &op);
            assert_eq!((v.res, v.ck, v.ik, v.ak), (h(res), h(ck), h(ik), h(ak)));
        }
    }
}
