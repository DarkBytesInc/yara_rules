rule Win_Trojan_Downloader_151
{
strings:
	$a0 = { 2b657a37387a36342e7a37347a36667a34377a3464747a35337a373472696e7a36372829 }
	$a1 = { 6576616c287a28246129293b }

condition:
	$a0 and $a1
}

        
