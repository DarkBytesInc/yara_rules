rule Win_Downloader_VB_1701
{
strings:
	$a0 = { 6d70616e6f000b02000360ea000007781e000008c0120000ff0381000000020600416469 }

condition:
	$a0
}

        
