rule Win_Downloader_Swizzor_567
{
strings:
	$a0 = { 313bd4448dfeba65ebf7b5faeec7e49f8cfe9fced1c46f39040bff24cfadceca440ab8e791f6363885777ad7c515b6ad1927fce75dca6a44b2871c1b7cafc58a4d8997ae5f1e0d731b24d0e89e57b21f78da2e0afe3d84bf41d5a1a5cce94027df7d16248b5c07cc624a8facc3ca }

condition:
	$a0
}

        
