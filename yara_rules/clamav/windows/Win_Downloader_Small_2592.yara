rule Win_Downloader_Small_2592
{
strings:
	$a0 = { ceef89e5b10e81ec9400000081ecfc0c000089e3b4c289254e4e4000a14c604000898314050000a14860400080ed5589 }

condition:
	$a0
}

        
