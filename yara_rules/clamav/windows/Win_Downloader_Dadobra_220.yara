rule Win_Downloader_Dadobra_220
{
strings:
	$a0 = { ae7a51705fa7be69b32facadd36b291bb6cb2f96bfe96ebd6b82c986ad4282fb6e2b3370953f6be5cb86b21ab34b729a83b3dd9ff9b0abf92bb03f44141874d8434387b712a40d9cf8db22696663bc6d98b345c85e86dad86edf }

condition:
	$a0
}

        
