rule Win_Downloader_5255_1
{
strings:
	$a0 = { be03044000f3a4515153680e04400051e83d0000004fbe2f0440006a0b59f3a45153e825000000 }

condition:
	$a0
}

        
