package verity.passport.prover

import java.math.BigInteger

/**
 * Computes the Barrett reduction parameter `mu` for a given modulus.
 *
 * Barrett reduction allows modular multiplication to be performed using
 * only multiplications and shifts, avoiding division at runtime.
 * The parameter `mu = floor(2^(2k + OVERFLOW_BITS) / n)` is precomputed
 * once per modulus and stored in the circuit witness.
 */
public object BarrettReduction {

    private const val BARRETT_REDUCTION_OVERFLOW_BITS = 4

    /**
     * Computes the raw Barrett reduction parameter `mu` for the given modulus.
     *
     * Strips any leading zero byte that [BigInteger.toByteArray] emits as a
     * sign bit, returning the minimal unsigned big-endian representation.
     *
     * @param modulus Big-endian unsigned byte representation of the modulus.
     * @return Minimal big-endian byte array for `mu`.
     */
    internal fun compute(modulus: ByteArray): ByteArray {
        val n = BigInteger(1, modulus)
        val k = n.bitLength()
        val twoTo2k = BigInteger.ONE.shiftLeft(2 * k + BARRETT_REDUCTION_OVERFLOW_BITS)
        val mu = twoTo2k.divide(n)
        return mu.toByteArray().let { bytes ->
            if (bytes.isNotEmpty() && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size)
            else bytes
        }
    }

    /**
     * Computes the Barrett reduction parameter `mu` right-padded into a fixed-size buffer.
     *
     * The value is written at the high end of a [size]-byte array (big-endian), which
     * matches the layout expected by the Noir circuit witness buffers.
     *
     * @param modulus Big-endian unsigned byte representation of the modulus.
     * @param size Exact byte length of the output buffer.
     * @return Big-endian `mu` value in a [size]-byte array.
     * @throws PassportError.BufferOverflow if `mu` does not fit in [size] bytes.
     */
    public fun computeFixed(modulus: ByteArray, size: Int): ByteArray {
        val mu = compute(modulus)
        if (mu.size > size) {
            throw PassportError.BufferOverflow("Barrett parameter ${mu.size} bytes exceeds buffer $size")
        }
        val result = ByteArray(size)
        mu.copyInto(result, destinationOffset = size - mu.size)
        return result
    }
}
