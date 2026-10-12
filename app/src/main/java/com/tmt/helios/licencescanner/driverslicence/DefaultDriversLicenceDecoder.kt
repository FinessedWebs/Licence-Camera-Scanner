package com.tmt.helios.licencescanner.driverslicence

import android.util.Base64
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.spec.RSAPublicKeySpec

class DefaultDriversLicenceDecoder :
    DriversLicenceDecoder {

    override fun decode(
        barcode: ByteArray
    ): DriversLicenceData {



        require(barcode.size >= 720) {
            "Driver licence barcode is too short: ${barcode.size} bytes"
        }

        android.util.Log.d(
            "DL_DECODER",
            "Received barcode: ${barcode.size} bytes"
        )

        val version =
            DriversLicenceVersionDetector.detect(barcode)

        android.util.Log.d(
            "DL_DECODER",
            "Version = $version"
        )

        val blocks =
            DriversLicenceBlockSplitter.split(barcode)

        blocks.forEachIndexed { index, block ->

            android.util.Log.d(
                "DL_DECODER",
                "Block ${index + 1} = ${block.size} bytes"
            )

            logBlock(
                blockNumber = index + 1,
                bytes = block
            )
        }



        /*
         * Existing South African driver's licence
         * barcode extraction logic.
         *
         * The original implementation skips the first
         * 6 bytes and uses the first 128-byte encrypted
         * block.
         */
        val slice =
            barcode.sliceArray(6 until 720)

        val encryptedBlocks =
            (0 until 5).map { index ->
                slice.sliceArray(
                    index * 128 until (index + 1) * 128
                )
            }

        val decryptedBlocks =
            encryptedBlocks.mapIndexed { index, encryptedBlock ->

                android.util.Log.d(
                    "DL_DECODER",
                    "Decrypting RSA block ${index + 1}"
                )

                val decrypted =
                    RsaDecryptor.decrypt(encryptedBlock)

                logBlock(
                    blockNumber = 101 + index,
                    bytes = decrypted
                )

                decrypted
            }

        decryptedBlocks.forEachIndexed { index, block ->

            val ascii =
                String(
                    block,
                    Charsets.ISO_8859_1
                )

            android.util.Log.d(
                "DL_FIELDS",
                "========== DECRYPTED BLOCK ${index + 101} =========="
            )

            android.util.Log.d(
                "DL_FIELDS",
                "HEX = ${block.joinToString(" ") {
                    "%02X".format(it)
                }}"
            )

            android.util.Log.d(
                "DL_FIELDS",
                "ASCII = $ascii"
            )
        }

        val details =
            parseLicenseDetails(
                decryptedBlocks[0]

            )

        android.util.Log.d(
            "DL_DECODER",
            "Decoded surname = ${details.surname}"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Decoded initials = ${details.initials}"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Decoded ID = ${details.id}"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Decoded licence number = ${details.licenseNumber}"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Decoded expiry = ${details.expiry}"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Issued = ${details.issued}"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Restriction = ${details.restriction}"
        )



        return DriversLicenceData(


            idNumber =
                details.id,

            surname =
                details.surname,

            firstNames =
                details.firstNames,

            initials =
                details.initials,

            gender =
                details.gender,

            dateOfBirth =
                details.dateOfBirth,

            licenceNumber =
                details.licenseNumber,

            issueDate =
                details.issueDate,

            expiryDate =
                details.expiry,

            vehicleCodes =
                details.vehicleCodes,

            issued =
                details.issued,

            restriction =
                details.restriction,

            firstIssued =
                details.firstIssued,

            vehicleRestriction =
                details.vehicleRestriction,

            driverRestriction =
                details.driverRestriction,

            rawBytes =
                barcode,

            countryOfIssue = details.countryOfIssue,
        )


        /*android.util.Log.d(
            "DL_DECODER",
            "Decoded surname = ${details.surname}"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Decoded initials = ${details.initials}"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Decoded ID = ${details.id}"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Decoded licence number = ${details.licenseNumber}"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Decoded expiry = ${details.expiry}"
        )

        return DriversLicenceData(
            idNumber = details.id,
            surname = details.surname,
            initials = details.initials,
            licenceNumber = details.licenseNumber,
            expiryDate = details.expiry,
            rawBytes = barcode
        )*/
    }

    private fun parseLicenseDetails(
        decrypted: ByteArray
    ): LicenseDetails {

        var index = 0

        /*
         * Find the beginning of the string section.
         *
         * The SA driver's licence format uses 0x82
         * as the marker before the string data.
         */
        while (
            index < decrypted.size &&
            decrypted[index].toInt() and 0xFF != 0x82
        ) {
            index++
        }

        require(index < decrypted.size) {
            "Could not find 0x82 string section marker"
        }

        /*
         * Skip:
         *
         * 0x82
         * length byte
         */
        index += 2

        /*
         * Vehicle codes
         *
         * The format contains up to four strings here.
         */
        /*
 * --------------------------------------------------
 * STRING DATA
 * --------------------------------------------------
 *
 * Observed V2 structure:
 *
 * 82 5B
 * C1 E1 E1 E1
 * MSIPA E0
 * M E1
 * ZA E0
 * ZA E0
 * 0 E1 E1 E1
 * 418000003KTZ E0
 * 0112085304080
 * 02
 */



        /*
         * Vehicle code
         *
         * Example:
         *
         * C1 E1 E1 E1
         */
        val vehicleCodeResult =
            readString(
                decrypted,
                index
            )

        val vehicleCodes =
            if (vehicleCodeResult.first.isNotBlank()) {
                listOf(vehicleCodeResult.first)
            } else {
                emptyList()
            }

        index =
            vehicleCodeResult.second

        /*
         * Skip remaining E1 delimiters after vehicle code.
         */
        while (
            index < decrypted.size &&
            (decrypted[index].toInt() and 0xFF) == 0xE1
        ) {
            index++
        }

        /*
         * Surname
         *
         * Example:
         *
         * MSIPA E0
         */
        val surnameResult =
            readString(
                decrypted,
                index
            )

        val surname =
            surnameResult.first

        index =
            surnameResult.second

        /*
         * Initials
         *
         * Example:
         *
         * M E1
         */
        val initialsResult =
            readString(
                decrypted,
                index
            )

        val initials =
            initialsResult.first

        index =
            initialsResult.second

        /*
         * Issued
         *
         * Example:
         *
         * ZA E0
         */
        val issuedResult =
            readString(
                decrypted,
                index
            )

        val issued =
            issuedResult.first

        index =
            issuedResult.second

        /*
         * Second ZA field.
         *
         * We are preserving it separately for now
         * instead of guessing its meaning.
         */
        val countryResult =
            readString(
                decrypted,
                index
            )

        val countryOfIssue =
            countryResult.first

        index =
            countryResult.second

        /*
         * Restriction
         *
         * Example:
         *
         * 0 E1 E1 E1
         */
        val restrictionResult =
            readString(
                decrypted,
                index
            )

        val restriction =
            restrictionResult.first

        index =
            restrictionResult.second

        /*
         * Skip remaining E1 delimiters.
         */
        while (
            index < decrypted.size &&
            (decrypted[index].toInt() and 0xFF) == 0xE1
        ) {
            index++
        }

        /*
         * Licence number
         *
         * Example:
         *
         * 418000003KTZ E0
         */
        val licenceNumberResult =
            readString(
                decrypted,
                index
            )

        val licenceNumber =
            licenceNumberResult.first

        index =
            licenceNumberResult.second

        /*
         * --------------------------------------------------
         * ID NUMBER
         * --------------------------------------------------
         *
         * The next 13 bytes are the ID number.
         *
         * Example:
         *
         * 0112085304080
         */
        require(index + 13 <= decrypted.size) {
            "Not enough bytes for ID number. index=$index size=${decrypted.size}"
        }

        val idNumber =
            decrypted
                .copyOfRange(
                    index,
                    index + 13
                )
                .toString(
                    StandardCharsets.US_ASCII
                )

        index += 13

        /*
         * ID number type
         */
        require(index < decrypted.size) {
            "Missing ID number type"
        }

        val idNumberType =
            decrypted[index].toInt() and 0xFF

        index++


        android.util.Log.d(
            "DL_DECODER",
            "Vehicle codes = $vehicleCodes"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Surname = $surname"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Initials = $initials"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Issued = $issued"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Country field = $countryOfIssue"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Restriction = $restriction"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Licence number = $licenceNumber"
        )

        android.util.Log.d(
            "DL_DECODER",
            "ID number = $idNumber"
        )

        android.util.Log.d(
            "DL_DECODER",
            "ID number type = $idNumberType"
        )


        android.util.Log.d(
            "DL_DECODER",
            "Vehicle codes = $vehicleCodes"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Surname = $surname"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Initials = $initials"
        )


        android.util.Log.d(
            "DL_DECODER",
            "Licence number = $licenceNumber"
        )

        android.util.Log.d(
            "DL_DECODER",
            "ID number = $idNumber"
        )

        android.util.Log.d(
            "DL_DECODER",
            "ID number type = $idNumberType"
        )

        /*
         * --------------------------------------------------
         * NIBBLE DATA
         * --------------------------------------------------
         *
         * Dates and several numeric fields are packed
         * as 4-bit nibbles.
         *
         * Continue until 0x57.
         */
        val nibbleQueue =
            mutableListOf<Int>()

        while (index < decrypted.size) {

            val current =
                decrypted[index].toInt() and 0xFF

            index++

            if (current == 0x57) {
                break
            }

            nibbleQueue.add(
                current shr 4
            )

            nibbleQueue.add(
                current and 0x0F
            )
        }

        /*
         * Four licence-code issue dates.
         */
        val licenceCodeIssueDates =
            readNibbleDateList(
                nibbleQueue,
                4
            )

        /*
         * Driver restriction code.
         */
        val driverRestrictionCode =
            readTwoDigitCode(
                nibbleQueue
            )

        /*
         * PrDP permit expiry date.
         */
        val prdpPermitExpiryDate =
            readNibbleDate(
                nibbleQueue
            )

        /*
         * Licence issue number.
         */
        val licenceIssueNumber =
            readTwoDigitCode(
                nibbleQueue
            )

        /*
         * Date of birth.
         */
        val dateOfBirth =
            readNibbleDate(
                nibbleQueue
            )

        /*
         * Licence issue date.
         */
        val issueDate =
            readNibbleDate(
                nibbleQueue
            )

        /*
         * Licence expiry date.
         */
        val expiryDate =
            readNibbleDate(
                nibbleQueue
            )

        /*
         * Gender.
         */
        val genderCode =
            readTwoDigitCode(
                nibbleQueue
            )

        val gender =
            when (genderCode) {
                "01" -> "Male"
                "02" -> "Female"
                else -> genderCode
            }

        android.util.Log.d(
            "DL_DECODER",
            "Licence code issue dates = $licenceCodeIssueDates"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Driver restriction = $driverRestrictionCode"
        )

        android.util.Log.d(
            "DL_DECODER",
            "PrDP expiry = $prdpPermitExpiryDate"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Licence issue number = $licenceIssueNumber"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Date of birth = $dateOfBirth"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Licence issue date = $issueDate"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Licence expiry date = $expiryDate"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Gender = $gender"


        )


        android.util.Log.d(
            "DL_DECODER",
            "========== PARSED LICENCE =========="
        )

        android.util.Log.d(
            "DL_DECODER",
            "Vehicle codes = $vehicleCodes"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Surname = $surname"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Initials = $initials"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Issued = $issued"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Country field = $countryOfIssue"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Restriction = $restriction"
        )

        android.util.Log.d(
            "DL_DECODER",
            "Licence number = $licenceNumber"
        )

        android.util.Log.d(
            "DL_DECODER",
            "ID number = $idNumber"
        )

        android.util.Log.d(
            "DL_DECODER",
            "ID number type = $idNumberType"
        )

        return LicenseDetails(
            initials = initials.trim(),
            surname = surname.trim(),
            id = idNumber.trim(),
            licenseNumber = licenceNumber.trim(),
            expiry = expiryDate.trim(),

            issued = issued.trim(),

            restriction = restriction.trim(),

            firstIssued =
                licenceCodeIssueDates
                    .firstOrNull()
                    .orEmpty(),

            vehicleRestriction =
                restriction.trim(),

            driverRestriction =
                driverRestrictionCode.trim(),

            firstNames = "",

            gender = gender,

            dateOfBirth = dateOfBirth,

            issueDate = issueDate,

            vehicleCodes = vehicleCodes,
            countryOfIssue = countryOfIssue.trim(),
        )
    }

    private fun readString(
        data: ByteArray,
        startIndex: Int
    ): Triple<String, Int, Int> {

        var index = startIndex

        val builder = StringBuilder()

        while (index < data.size) {

            val value =
                data[index].toInt() and 0xFF

            index++

            when (value) {

                0xE0 -> {
                    return Triple(
                        builder.toString(),
                        index,
                        0xE0
                    )
                }

                0xE1 -> {
                    return Triple(
                        builder.toString(),
                        index,
                        0xE1
                    )
                }

                else -> {
                    builder.append(value.toChar())
                }
            }
        }

        return Triple(
            builder.toString(),
            index,
            0xE0
        )
    }

    private fun readStrings(
        data: ByteArray,
        startIndex: Int,
        count: Int
    ): Pair<List<String>, Int> {

        val values = mutableListOf<String>()

        var index = startIndex

        while (
            index < data.size &&
            values.size < count
        ) {

            val result =
                readString(
                    data,
                    index
                )

            val value = result.first

            index = result.second

            if (value.isNotEmpty()) {
                values.add(value)
            }

            /*
             * If we hit E1, there may be another
             * E1 immediately after it.
             *
             * Skip consecutive delimiters.
             */
            while (
                index < data.size &&
                (data[index].toInt() and 0xFF) == 0xE1
            ) {
                index++
            }

            /*
             * E0 marks the end of this section.
             *
             * Do not blindly continue parsing more
             * strings beyond it.
             */
            if (
                index < data.size &&
                (data[index].toInt() and 0xFF) == 0xE0
            ) {
                index++
                break
            }
        }

        return Pair(
            values,
            index
        )
    }

    private fun readNibbleDate(
        queue: MutableList<Int>
    ): String {

        if (queue.isEmpty()) {
            return ""
        }

        val first =
            queue.removeAt(0)

        /*
         * 10 represents an empty date.
         */
        if (first == 10) {
            return ""
        }

        if (queue.size < 7) {
            return ""
        }

        val century =
            queue.removeAt(0)

        val decade =
            queue.removeAt(0)

        val year =
            queue.removeAt(0)

        val month1 =
            queue.removeAt(0)

        val month2 =
            queue.removeAt(0)

        val day1 =
            queue.removeAt(0)

        val day2 =
            queue.removeAt(0)

        return "$first$century$decade$year/" +
                "$month1$month2/" +
                "$day1$day2"
    }

    private fun readNibbleDateList(
        queue: MutableList<Int>,
        count: Int
    ): List<String> {

        val dates =
            mutableListOf<String>()

        repeat(count) {

            val date =
                readNibbleDate(queue)

            if (date.isNotEmpty()) {
                dates.add(date)
            }
        }

        return dates
    }

    private fun readTwoDigitCode(
        queue: MutableList<Int>
    ): String {

        if (queue.size < 2) {
            return ""
        }

        val first =
            queue.removeAt(0)

        val second =
            queue.removeAt(0)

        return "$first$second"
    }



    private fun extractExpiry(
        hex: String
    ): String {

        val parts =
            hex.split("e0")

        val index4 =
            parts.getOrNull(4)

        return if (
            index4 != null &&
            index4.length < 68
        ) {
            parts
                .getOrNull(6)
                ?.takeIf { it.length >= 75 }
                ?.substring(67, 75)
                ?: ""
        } else {
            index4
                ?.takeIf { it.length >= 68 }
                ?.substring(60, 68)
                ?: ""
        }
    }

    private fun byteArrayToHex(
        byteArray: ByteArray
    ): String =
        byteArray.joinToString("") {
            "%02x".format(it)
        }
}

private fun logBlock(
    blockNumber: Int,
    bytes: ByteArray
) {
    val hex = bytes.joinToString(" ") {
        "%02X".format(it.toInt() and 0xFF)
    }

    val ascii = bytes.map { byte ->
        val value = byte.toInt() and 0xFF

        if (value in 32..126) {
            value.toChar()
        } else {
            '.'
        }
    }.joinToString("")

    android.util.Log.d(
        "DL_RAW",
        "BLOCK $blockNumber SIZE=${bytes.size}"
    )

    android.util.Log.d(
        "DL_RAW",
        "BLOCK $blockNumber HEX=$hex"
    )

    android.util.Log.d(
        "DL_RAW",
        "BLOCK $blockNumber ASCII=$ascii"
    )
}

private data class LicenseDetails(
    val initials: String,
    val surname: String,
    val id: String,
    val licenseNumber: String,
    val expiry: String,
    val issued: String,
    val restriction: String,
    val firstIssued: String,
    val vehicleRestriction: String,
    val driverRestriction: String,
    val firstNames: String,
    val gender: String,
    val dateOfBirth: String,
    val issueDate: String,
    val countryOfIssue: String,
    val vehicleCodes: List<String>
)

private object RsaDecryptor {

    private const val RSA_BLOCK_SIZE = 128

    private const val RSA_PUBLIC_KEY = """
        -----BEGIN RSA PUBLIC KEY-----
        MIGWAoGBAMqfGO9sPz+kxaRh/qVKsZQGul7NdG1gonSS3KPXTjtcHTFfexA4MkGA
        mwKeu9XeTRFgMMxX99WmyaFvNzuxSlCFI/foCkx0TZCFZjpKFHLXryxWrkG1Bl9+
        +gKTvTJ4rWk1RvnxYhm3n/Rxo2NoJM/822Oo7YBZ5rmk8NuJU4HLAhAYcJLaZFTO
        sYU+aRX4RmoF
        -----END RSA PUBLIC KEY-----
    """

    fun decrypt(
        input: ByteArray
    ): ByteArray {

        val (modulus, publicExponent) =
            parseRsaPublicKey()

        val rsaPublicKeySpec =
            RSAPublicKeySpec(
                modulus,
                publicExponent
            )

        return rsaOperation(
            input,
            rsaPublicKeySpec.publicExponent,
            rsaPublicKeySpec.modulus
        )
    }

    private fun parseRsaPublicKey():
            Pair<BigInteger, BigInteger> {

        val encoded =
            RSA_PUBLIC_KEY
                .replace(
                    "-----(BEGIN|END) RSA PUBLIC KEY-----"
                        .toRegex(),
                    ""
                )
                .replace("\n", "")
                .replace("\r", "")

        val keyBytes =
            Base64.decode(
                encoded,
                Base64.DEFAULT
            )

        org.bouncycastle.asn1.ASN1InputStream(
            keyBytes
        ).use { asn1Is ->

            val sequence =
                asn1Is.readObject()
                        as org.bouncycastle.asn1.DLSequence

            val modulus =
                sequence.getObjectAt(0)
                        as org.bouncycastle.asn1.ASN1Integer

            val exponent =
                sequence.getObjectAt(1)
                        as org.bouncycastle.asn1.ASN1Integer

            return Pair(
                modulus.positiveValue,
                exponent.positiveValue
            )
        }
    }

    private fun rsaOperation(
        input: ByteArray,
        exponent: BigInteger,
        modulus: BigInteger
    ): ByteArray {

        val padded =
            addLeadingZeros(
                input,
                RSA_BLOCK_SIZE + 1
            )

        val value =
            BigInteger(padded)

        val output =
            value.modPow(
                exponent,
                modulus
            )

        return output.toByteArray()
    }

    private fun addLeadingZeros(
        byteArray: ByteArray,
        totalLength: Int
    ): ByteArray {

        if (byteArray.size >= totalLength) {
            return byteArray.sliceArray(
                0 until totalLength
            )
        }

        val padded =
            ByteArray(totalLength)

        System.arraycopy(
            byteArray,
            0,
            padded,
            totalLength - byteArray.size,
            byteArray.size
        )

        return padded
    }
}
