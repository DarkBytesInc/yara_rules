rule Win_Downloader_Banload_1819
{
strings:
	$a0 = { ffe4caffffe4caffffe4caffffe4caffffe5c9ffffe4caffffe5c9ffffe5caffffe5caffffe4caffffe4c9ffffe4caffffe4caffffe4caffffccafff936563ff0000008f0000002f0000000000000000a876240ccf9831bcf5bb3cfff6bb39fff1b232ffedaa2dffe8 }

condition:
	$a0
}

        
