rule Win_Downloader_Swizzor_487
{
strings:
	$a0 = { 07bda9aca413d6938130cfa4e4687838cba260759bf4777085fb2a62a5f2320c394b2e6adcaa272aaa7db6cfffa304d057411e39f225f21efa146ce58e5fd445743844f1239401907f278c161981 }

condition:
	$a0
}

        
