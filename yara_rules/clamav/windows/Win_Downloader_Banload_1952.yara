rule Win_Downloader_Banload_1952
{
strings:
	$a0 = { f3f3f31c181410f3f3f3f30c080400f8f8f1f1fca0f844a1f43f3e7e7ca0f05ca158870f1f3f54eca064a1e8a0164e33405383c4bcbb0a54e80edb020020dbf644242c0174050fb75c24308bc3ef8bd605445bc3e49f1f8b8fe0a0dcd89d9f9f9fd4d0ccc8130064815356bedc95833e00753a684406006427986a00015f8bc885c9750533105c2027c05ea1 }

condition:
	$a0
}

        