package com.tmt.helios.licencescanner

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.Gravity
import android.widget.FrameLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.OptIn
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import com.tmt.helios.licencescanner.driverslicence.DefaultDriversLicenceDecoder
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : ComponentActivity() {

    private lateinit var previewView: PreviewView
    private lateinit var statusText: TextView
    private lateinit var cameraExecutor: ExecutorService
    private lateinit var decoderExecutor: ExecutorService

    @Volatile
    private var barcodeDetected = false

    @Volatile
    private var decodingInProgress = false

    @Volatile
    private var scannedPayload: ByteArray? = null

    private val licenceDecoder = DefaultDriversLicenceDecoder()

    private val barcodeScanner by lazy {
        BarcodeScanning.getClient(
            com.google.mlkit.vision.barcode.BarcodeScannerOptions.Builder()
                .setBarcodeFormats(Barcode.FORMAT_PDF417)
                .build()
        )
    }

    private val cameraPermissionLauncher =
        registerForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { granted ->
            if (granted) {
                startCamera()
            } else {
                statusText.text = "Camera permission is required to scan licences."
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        cameraExecutor = Executors.newSingleThreadExecutor()
        decoderExecutor = Executors.newSingleThreadExecutor()

        previewView = PreviewView(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }

        statusText = TextView(this).apply {
            text = "Starting camera..."
            textSize = 18f
            setTextColor(android.graphics.Color.WHITE)
            setBackgroundColor(0x99000000.toInt())
            setPadding(24, 20, 24, 20)
        }

        val root = FrameLayout(this)
        root.addView(previewView)
        root.addView(
            statusText,
            FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.TOP
            }
        )

        setContentView(root)

        if (
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            startCamera()
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private fun startCamera() {
        statusText.text = "Opening camera..."

        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)

        cameraProviderFuture.addListener({
            try {
                val cameraProvider = cameraProviderFuture.get()

                val preview = Preview.Builder().build().also {
                    it.setSurfaceProvider(previewView.surfaceProvider)
                }

                val analysis = ImageAnalysis.Builder()
                    .setResolutionSelector(
                        androidx.camera.core.resolutionselector.ResolutionSelector.Builder()
                            .setResolutionStrategy(
                                androidx.camera.core.resolutionselector.ResolutionStrategy(
                                    android.util.Size(1280, 720),
                                    androidx.camera.core.resolutionselector.ResolutionStrategy
                                        .FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER
                                )
                            )
                            .build()
                    )
                    .setBackpressureStrategy(
                        ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST
                    )
                    .build()

                analysis.setAnalyzer(cameraExecutor) { imageProxy ->
                    processImage(imageProxy)
                }

                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(
                    this,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis
                )

                statusText.text = "Camera ready — scan a PDF417 barcode."
            } catch (exception: Exception) {
                statusText.text =
                    "Camera error: ${exception.localizedMessage}"
                android.util.Log.e(
                    "LicenceScanner",
                    "Failed to start camera",
                    exception
                )
            }
        }, ContextCompat.getMainExecutor(this))
    }

    @OptIn(ExperimentalGetImage::class)
    private fun processImage(imageProxy: ImageProxy) {
        if (barcodeDetected || decodingInProgress) {
            imageProxy.close()
            return
        }

        val mediaImage = imageProxy.image
        if (mediaImage == null) {
            android.util.Log.w("LicenceScanner", "Camera image is null")
            imageProxy.close()
            return
        }

        val inputImage = InputImage.fromMediaImage(
            mediaImage,
            imageProxy.imageInfo.rotationDegrees
        )

        barcodeScanner.process(inputImage)
            .addOnSuccessListener { barcodes ->
                val barcode = barcodes.firstOrNull {
                    it.format == Barcode.FORMAT_PDF417
                }

                if (barcode != null) {
                    val rawValue = barcode.rawValue
                    val rawBytes = barcode.rawBytes

                    android.util.Log.d(
                        "LicenceScanner",
                        "PDF417 detected: " +
                                "format=${barcode.format}, " +
                                "valueType=${barcode.valueType}, " +
                                "rawValueLength=${rawValue?.length ?: 0}, " +
                                "rawBytesLength=${rawBytes?.size ?: 0}"
                    )

                    if (rawBytes != null && rawBytes.isNotEmpty()) {
                        val payload = rawBytes.copyOf()
                        scannedPayload = payload
                        barcodeDetected = true
                        decodingInProgress = true

                        android.util.Log.d(
                            "LicenceScanner",
                            "Saved PDF417 payload: ${payload.size} bytes"
                        )

                        runOnUiThread {
                            statusText.text =
                                "Barcode captured (${payload.size} bytes). Decoding licence..."
                        }

                        decodePayload(payload)
                    } else {
                        runOnUiThread {
                            statusText.text =
                                "PDF417 detected, but binary payload is empty."
                        }
                    }
                }
            }
            .addOnFailureListener { exception ->
                android.util.Log.e(
                    "LicenceScanner",
                    "Barcode analysis failed",
                    exception
                )

                runOnUiThread {
                    statusText.text =
                        "Scan error: ${exception.localizedMessage}"
                }
            }
            .addOnCompleteListener {
                imageProxy.close()
            }
    }

    private fun decodePayload(payload: ByteArray) {
        decoderExecutor.execute {
            try {
                val licence = licenceDecoder.decode(payload)

                android.util.Log.d(
                    "LicenceScanner",
                    "Licence decoded successfully. " +
                            "Surname=${licence.surname}, " +
                            "LicenceNumber=${licence.licenceNumber}"
                )

                runOnUiThread {
                    statusText.text = """
                        Licence decoded successfully

                        Surname: ${licence.surname}
                        Initials: ${licence.initials}
                        First names: ${licence.firstNames}
                        ID number: ${licence.idNumber}
                        Date of birth: ${licence.dateOfBirth}
                        Gender: ${licence.gender}
                        Licence number: ${licence.licenceNumber}
                        Issue date: ${licence.issueDate}
                        Expiry date: ${licence.expiryDate}
                        Vehicle codes: ${licence.vehicleCodes.joinToString(", ")}
                        Issued: ${licence.issued}
                        Country of issue: ${licence.countryOfIssue}
                        Restriction: ${licence.restriction}
                    """.trimIndent()
                }
            } catch (exception: Exception) {
                android.util.Log.e(
                    "LicenceScanner",
                    "Licence decoding failed",
                    exception
                )

                runOnUiThread {
                    statusText.text =
                        "Barcode captured (${payload.size} bytes), but decoding failed:\n" +
                                (exception.localizedMessage ?: exception.javaClass.simpleName)
                }
            } finally {
                decodingInProgress = false
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()

        if (::cameraExecutor.isInitialized) {
            cameraExecutor.shutdown()
        }

        if (::decoderExecutor.isInitialized) {
            decoderExecutor.shutdown()
        }

        barcodeScanner.close()
    }
}
