package verity.passport.prover

import java.math.BigInteger

/**
 * Poseidon2 hash function implementation over the BN254 scalar field.
 *
 * Implements the sponge construction with a 4-element state (rate=3, capacity=1),
 * using the round constants and internal matrix diagonal defined in [Poseidon2Constants].
 * All arithmetic is performed modulo [P] (the BN254 scalar field prime).
 */
public object Poseidon2 {

    /** BN254 scalar field prime. */
    public val P: BigInteger = BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617")

    private val ZERO = BigInteger.ZERO
    private val RATE = 3
    private val TWO_POW_64 = BigInteger.ONE.shiftLeft(64)

    private fun add(a: BigInteger, b: BigInteger): BigInteger = (a + b).mod(P)
    private fun mul(a: BigInteger, b: BigInteger): BigInteger = (a * b).mod(P)

    private fun sBox(x: BigInteger): BigInteger {
        val s = mul(x, x)
        return mul(mul(s, s), x)
    }

    private fun matMul4x4(state: Array<BigInteger>) {
        val t0 = add(state[0], state[1])
        val t1 = add(state[2], state[3])
        var t2 = add(state[1], state[1])
        t2 = add(t2, t1)
        var t3 = add(state[3], state[3])
        t3 = add(t3, t0)
        var t4 = add(t1, t1)
        t4 = add(t4, t4)
        t4 = add(t4, t3)
        var t5 = add(t0, t0)
        t5 = add(t5, t5)
        t5 = add(t5, t2)
        val t6 = add(t3, t5)
        val t7 = add(t2, t4)
        state[0] = t6
        state[1] = t5
        state[2] = t7
        state[3] = t4
    }

    private fun internalMatMul(state: Array<BigInteger>, diag: Array<BigInteger>) {
        var sum = ZERO
        for (s in state) sum = add(sum, s)
        for (i in state.indices) {
            state[i] = add(mul(state[i], diag[i]), sum)
        }
    }

    /**
     * Applies the full Poseidon2 permutation to a 4-element state.
     *
     * Consists of [rfFirst] full rounds, [rp] partial rounds, and [rfFirst] more full rounds,
     * using the round constants from [Poseidon2Constants.ROUND_CONSTANTS] and the
     * internal matrix diagonal from [Poseidon2Constants.INTERNAL_MATRIX_DIAGONAL].
     *
     * @param inputs 4-element array of field elements to permute.
     * @return A new 4-element array containing the permuted state.
     */
    public fun permutation(inputs: Array<BigInteger>): Array<BigInteger> {
        val rfFirst = 4
        val rp = 56
        val pEnd = rfFirst + rp
        val numRounds = rfFirst + rp + rfFirst

        val state = inputs.copyOf()
        val rc = Poseidon2Constants.ROUND_CONSTANTS
        val diag = Poseidon2Constants.INTERNAL_MATRIX_DIAGONAL

        matMul4x4(state)

        for (r in 0 until rfFirst) {
            for (i in 0..3) state[i] = add(state[i], rc[r][i])
            for (i in 0..3) state[i] = sBox(state[i])
            matMul4x4(state)
        }

        for (r in rfFirst until pEnd) {
            state[0] = add(state[0], rc[r][0])
            state[0] = sBox(state[0])
            internalMatMul(state, diag)
        }

        for (r in pEnd until numRounds) {
            for (i in 0..3) state[i] = add(state[i], rc[r][i])
            for (i in 0..3) state[i] = sBox(state[i])
            matMul4x4(state)
        }

        return state
    }

    /**
     * Hashes a list of field elements using the Poseidon2 sponge construction.
     *
     * The capacity element is initialised as `len(inputs) * 2^64` to provide
     * domain separation. Inputs are absorbed [RATE] elements at a time; the
     * permutation is applied whenever the internal cache is full. The first
     * element of the final permuted state is returned as the digest.
     *
     * @param inputs List of BN254 field elements to hash.
     * @return The Poseidon2 hash as a [BigInteger] field element.
     */
    public fun hash(inputs: List<BigInteger>): BigInteger {
        val iv = mul(BigInteger.valueOf(inputs.size.toLong()), TWO_POW_64)

        val state = arrayOf(ZERO, ZERO, ZERO, iv)
        val cache = arrayOf(ZERO, ZERO, ZERO)
        var cacheSize = 0

        for (input in inputs) {
            if (cacheSize == RATE) {
                for (i in 0 until RATE) state[i] = add(state[i], cache[i])
                cache[0] = ZERO; cache[1] = ZERO; cache[2] = ZERO
                cacheSize = 0
                val perm = permutation(state)
                state[0] = perm[0]; state[1] = perm[1]; state[2] = perm[2]; state[3] = perm[3]
            }
            cache[cacheSize] = input
            cacheSize++
        }

        for (i in 0 until cacheSize) state[i] = add(state[i], cache[i])
        val result = permutation(state)

        return result[0]
    }

    /**
     * Hashes one or more hex-encoded field elements using the Poseidon2 sponge construction.
     *
     * Each string is decoded via [hexToField] before hashing.
     *
     * @param hexInputs Hex-encoded field element strings (with or without `0x` prefix).
     * @return The Poseidon2 hash as a [BigInteger] field element.
     */
    public fun hash(vararg hexInputs: String): BigInteger {
        return hash(hexInputs.map { hexToField(it) })
    }

    /**
     * Decodes a hex string into a BN254 field element, reducing modulo [P].
     *
     * @param hex Hex string with optional `0x` prefix.
     * @return The field element as a [BigInteger] in `[0, P)`.
     */
    public fun hexToField(hex: String): BigInteger {
        val s = if (hex.startsWith("0x")) hex.substring(2) else hex
        return BigInteger(s, 16).mod(P)
    }

    /**
     * Encodes a BN254 field element as a zero-padded 32-byte hex string with `0x` prefix.
     *
     * @param fe Field element to encode; reduced modulo [P] before encoding.
     * @return Hex string of the form `"0x" + 64 hex digits`.
     */
    public fun fieldToHex(fe: BigInteger): String {
        return "0x" + fe.mod(P).toString(16).padStart(64, '0')
    }

    /**
     * Packs a byte array into a list of BN254 field elements in little-endian field order.
     *
     * Bytes are grouped into chunks of up to [bytesPerField] bytes each. The first chunk
     * may be smaller than [bytesPerField] to consume the leading bytes. Each chunk is
     * interpreted as a big-endian unsigned integer and reduced modulo [P]. The resulting
     * list is reversed so that the chunk containing the lowest-address bytes appears last,
     * matching the Noir circuit packing convention.
     *
     * @param bytes Raw bytes to pack.
     * @param bytesPerField Maximum bytes per field element (default 31, safe for BN254).
     * @return List of field elements in little-endian field order.
     */
    public fun packBytesIntoFields(bytes: ByteArray, bytesPerField: Int = 31): List<BigInteger> {
        val numFields = (bytes.size + bytesPerField - 1) / bytesPerField
        val firstFieldSize = bytes.size - (numFields - 1) * bytesPerField
        var offset = 0

        return buildList(numFields) {
            var value = ZERO
            for (i in 0 until firstFieldSize) {
                value = value.shiftLeft(8).add(BigInteger.valueOf((bytes[offset++].toInt() and 0xFF).toLong()))
            }
            add(value.mod(P))

            for (f in 1 until numFields) {
                value = ZERO
                for (i in 0 until bytesPerField) {
                    value = value.shiftLeft(8).add(BigInteger.valueOf((bytes[offset++].toInt() and 0xFF).toLong()))
                }
                add(value.mod(P))
            }
        }.reversed()
    }
}
