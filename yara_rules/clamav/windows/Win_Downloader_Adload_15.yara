rule Win_Downloader_Adload_15
{
strings:
	$a0 = { 3c000000700072006f006d006f002e0064006f006c006c006100720072006500760065006e00750065002e0063006f006d002f00620075006e0064006c006500000000000400000049004400000000006a0000006800740074 }

condition:
	$a0
}

        