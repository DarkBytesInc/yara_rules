rule Win_Downloader_Small_2187
{
strings:
	$a0 = { e580c68481ec9400000081ecfc0c000080ee0089e380e993892507254000a144604000b11f8983a2000000a14860400080f1e98983a50b0000c783410800000000000080e56980e188c783ac030000000000 }

condition:
	$a0
}

        