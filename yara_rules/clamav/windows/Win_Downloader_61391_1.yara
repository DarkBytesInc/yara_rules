rule Win_Downloader_61391_1
{
strings:
	$a0 = { 89e18b0131ff40333885ff75f7e815000000ab0093d70079003f000016003d00d6cf00a00036005a6683c76e }

condition:
	$a0
}

        
