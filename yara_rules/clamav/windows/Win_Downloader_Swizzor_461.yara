rule Win_Downloader_Swizzor_461
{
strings:
	$a0 = { 47ec746429c5e2da87aa3879439a1794888d496d2b27055279a574da66a6e3a641dc65587b369a2eb10caf04f9cf96d4583695d1f4b3fccac322ade2356c8373907d8acaa24c11d4afa1dc5b42f7bd439dda25d515e437f8aff4 }

condition:
	$a0
}

        
