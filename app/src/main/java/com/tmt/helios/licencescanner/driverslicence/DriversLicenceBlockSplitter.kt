package com.tmt.helios.licencescanner.driverslicence

object DriversLicenceBlockSplitter {

    fun split(barcode: ByteArray): List<ByteArray> {

        require(barcode.size == 720) {
            "Expected 720 bytes."
        }

        // Skip version (4 bytes) + reserved bytes (2 bytes)
        val payload = barcode.copyOfRange(6, barcode.size)

        require(payload.size == 714)

        return listOf(
            payload.copyOfRange(0, 128),
            payload.copyOfRange(128, 256),
            payload.copyOfRange(256, 384),
            payload.copyOfRange(384, 512),
            payload.copyOfRange(512, 640),
            payload.copyOfRange(640, 714)
        )
    }
}