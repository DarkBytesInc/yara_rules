rule Win_Downloader_Small_2506
{
strings:
	$a0 = { 89e580e5ce81ec9400000081ecfc0c000089e38925f6104000a12c604000b4e28983060c0000a12860400089432ac783b50c00000000000080e915b281c783d50c }

condition:
	$a0
}

        