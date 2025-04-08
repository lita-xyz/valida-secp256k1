pub const R_GEN: ([u8; 32], [u8; 32]) = {
    match (
        const_hex::const_decode_to_array(
            b"0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
        const_hex::const_decode_to_array(
            b"0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        ),
    ) {
        (Ok(a), Ok(b)) => ({ reverse_array(a) }, { reverse_array(b) }),
        _ => panic!("Failed to decode hex values"),
    }
};

const fn reverse_array<T, const N: usize>(mut arr: [T; N]) -> [T; N]
where
    T: Copy,
{
    let mut i = 0;
    let mut j = N;

    if N == 0 {
        return arr;
    }

    while i < j - 1 {
        j -= 1;
        let temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
        i += 1;
    }

    arr
}
