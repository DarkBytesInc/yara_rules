rule Win_Downloader_Swizzor_449
{
strings:
	$a0 = { eb989a1eb835eb81946b12753a3f48463b37301cbdb1add52aaf9249d808e8f1fe85dfdb7abcd8fa7b91bafe58349d2868cbd8d0e85c99f0d410da9c8eda83607cfb53b3189b692fdbfffcdf3954f9eccba3e7e009bce05922fa }

condition:
	$a0
}

        
