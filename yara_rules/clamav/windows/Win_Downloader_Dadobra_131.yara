rule Win_Downloader_Dadobra_131
{
strings:
	$a0 = { d49c16369b1c808d4797ec0d5cf81ee88d455ec4cbc84ab6ca1d6a74c51b45f6ed59cbc15d025787cb0ef9a4747333ad04761170fd88583d768bbce03d7495a8932893fef97085f8cda05694e9dd453fcc7d936db1939a02afe78ecc7ed080bfd3ec8d246bceb775c1d90d5e }

condition:
	$a0
}

        
