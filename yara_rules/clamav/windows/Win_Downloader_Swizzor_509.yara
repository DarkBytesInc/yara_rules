rule Win_Downloader_Swizzor_509
{
strings:
	$a0 = { 7471cc98d076590ebcb1f0ef9d82f54ba2cb2545bf345ed5bd65fffd0b5d1e0585af36b157afad9cc4895fce1751e1fc06ca57e3d798c538435c5eeea8bc5fdbc43823fba62b7e2b454e8a7d2408adf18badccc9ad953260c9288ed6d4eab89ff77575402702c51096 }

condition:
	$a0
}

        
