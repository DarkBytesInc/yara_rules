rule Win_Downloader_Banload_1815
{
strings:
	$a0 = { caffffe5caffffe4caffffe4c9ffffe4c9ffffe4c9ffffe5c9ffffe5caffffe4c9ffffe4c9ffffe4caffffe4caffffe4caffffe4caffffe5c9ffffe4caffffe5c9ffffe5caffffe5caffffe4caffffe4c9ffffe4caffffe4caffffe4caffffccafff936563ff000000 }

condition:
	$a0
}

        
