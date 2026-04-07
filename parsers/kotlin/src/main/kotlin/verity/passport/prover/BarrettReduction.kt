package verity.passport.prover

import java.math.BigInteger

object BarrettReduction {

    private const val BARRETT_REDUCTION_OVERFLOW_BITS = 4

    fun compute(modulus: ByteArray): ByteArray {
        val n = BigInteger(1, modulus)
        val k = n.bitLength()
        val twoTo2k = BigInteger.ONE.shiftLeft(2 * k + BARRETT_REDUCTION_OVERFLOW_BITS)
        val mu = twoTo2k.divide(n)
        val muBytes = mu.toByteArray()
        return if (muBytes.isNotEmpty() && muBytes[0] == 0.toByte()) {
            muBytes.copyOfRange(1, muBytes.size)
        } else {
            muBytes
        }
    }

    fun computeFixed(modulus: ByteArray, size: Int): ByteArray {
        val mu = compute(modulus)
        if (mu.size > size) {
            throw PassportError.BufferOverflow("Barrett parameter ${mu.size} bytes exceeds buffer $size")
        }
        val result = ByteArray(size)
        mu.copyInto(result, destinationOffset = size - mu.size)
        return result
    }
}
