rule Win_Downloader_Swizzor_492
{
strings:
	$a0 = { 79224ec38c830078f2b17f44f3a34bcabbdb8260dd4cdc9a5d3778416eea283016bcf5d49acb3794444389255aa7da7f9a50ba3252c75ec6a5639792b72576b261a400f255107ad8fca08350f3c0 }

condition:
	$a0
}

        
