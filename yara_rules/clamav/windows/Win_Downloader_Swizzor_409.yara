rule Win_Downloader_Swizzor_409
{
strings:
	$a0 = { 1c35d526af6e4df8a20b596e01adc92246bef4012d0e54a12242667491604e1a24d4d5881afea110cf5e6ff807f9caa63bf7613d6644f108ddac5598ce38ede515a82751f492e660507329dabae654c18ae947ae36e25da93bc0 }

condition:
	$a0
}

        
