package com.tmt.helios.licencescanner.driverslicence

data class DriversLicenceData(

    val idNumber: String = "",
    val surname: String = "",
    val firstNames: String = "",
    val initials: String = "",
    val gender: String = "",
    val dateOfBirth: String = "",
    val licenceNumber: String = "",
    val issueDate: String = "",
    val expiryDate: String = "",
    val vehicleCodes: List<String> = emptyList(),
    val issued: String = "",
    val restriction: String = "",
    val firstIssued: String = "",
    val vehicleRestriction: String = "",
    val driverRestriction: String = "",
    val rawBytes: ByteArray = byteArrayOf(),
    val countryOfIssue: String,
)