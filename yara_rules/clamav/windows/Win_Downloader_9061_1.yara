rule Win_Downloader_9061_1
{
strings:
	$a0 = { 6a0aff157610400068121140006affff156a10400089c1330d1211400081f141595632bb9f000000 }

condition:
	$a0
}

        
