rule Win_Downloader_Swizzor_404
{
strings:
	$a0 = { e4d6c4b962c7d09812b3017bdf2651aa14222b764bb72f0a3fa1862e93d45579c5add45a2ab9b8536b70b678da815f142ba4731c0fce2645c0a182adb6113ea09d2870dbe65e0a5e9c35c374acd9b8965ba2bdfa4638422f4c0d }

condition:
	$a0
}

        
