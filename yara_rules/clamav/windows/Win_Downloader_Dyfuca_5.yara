rule Win_Downloader_Dyfuca_5
{
strings:
	$a0 = { 3a1b726e616d653a43446f7766a08bf86e6c6f616448503f1cddf677ff20576169742e2e5c3230332e31363603390b31e7b7ef973734352e373617340b37372e3932c2edd6ba381f32030800362e39308a6fe79e838b2f373332353b75ddd79a3031190b3013341b33375df7bf0c687474703a2f2f002f2f }

condition:
	$a0
}

        