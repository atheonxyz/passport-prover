package verity.passport.prover

import java.math.BigInteger

object Poseidon2 {

    val P: BigInteger = BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617")

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

    fun permutation(inputs: Array<BigInteger>): Array<BigInteger> {
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

    fun hash(inputs: List<BigInteger>): BigInteger {
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

    fun hash(vararg hexInputs: String): BigInteger {
        return hash(hexInputs.map { hexToField(it) })
    }

    fun hexToField(hex: String): BigInteger {
        val s = if (hex.startsWith("0x")) hex.substring(2) else hex
        return BigInteger(s, 16).mod(P)
    }

    fun fieldToHex(fe: BigInteger): String {
        return "0x" + fe.mod(P).toString(16).padStart(64, '0')
    }

    fun packBytesIntoFields(bytes: ByteArray, bytesPerField: Int = 31): List<BigInteger> {
        val numFields = (bytes.size + bytesPerField - 1) / bytesPerField
        val fields = mutableListOf<BigInteger>()

        val firstFieldSize = bytes.size - (numFields - 1) * bytesPerField
        var offset = 0

        var value = ZERO
        for (i in 0 until firstFieldSize) {
            value = value.shiftLeft(8).add(BigInteger.valueOf((bytes[offset++].toInt() and 0xFF).toLong()))
        }
        fields.add(value.mod(P))

        for (f in 1 until numFields) {
            value = ZERO
            for (i in 0 until bytesPerField) {
                value = value.shiftLeft(8).add(BigInteger.valueOf((bytes[offset++].toInt() and 0xFF).toLong()))
            }
            fields.add(value.mod(P))
        }

        return fields.reversed()
    }
}
