package com.tmt.helios.licencescanner.driverslicence

interface DriversLicenceDecoder {

    fun decode(
        barcode: ByteArray
    ): DriversLicenceData
}