package com.tmt.helios.licencescanner.driverslicence

object DriversLicenceVersionDetector {

    fun detect(
        barcode: ByteArray
    ): DriversLicenceVersion {

        require(barcode.size == 720) {
            "Expected 720 bytes but got ${barcode.size}"
        }

        val header = barcode.copyOfRange(0, 4)

        return when {
            header.contentEquals(
                DriversLicenceConstants.VERSION1
            ) -> DriversLicenceVersion.V1

            header.contentEquals(
                DriversLicenceConstants.VERSION2
            ) -> DriversLicenceVersion.V2

            else -> error(
                "Unknown licence version."
            )
        }
    }
}