rule Win_Downloader_Wintrim_11
{
strings:
	$a0 = { 74703a2f2f33353601332e89742f9bfd0ffb1f2f173735747a2e636f6d152f0fcc8c2d46641b49455daab1bb4609534c55c772e25365ea9a7fbba27068bf6500524144005c }

condition:
	$a0
}

        
