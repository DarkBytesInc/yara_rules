rule Win_Downloader_Banload_1549
{
strings:
	$a0 = { 3fffc2a891fff5ddc6ffffe9d3ffffe9d3ffffe9d3ffffe9d3ffffe9d3ffffe9d3ffffe9d3ffffe9d3ffffccb4ff9b6d6bff0000008f0000002f00000000c5a54c33e2bb69e6d2b05c2200000000cca33f65e8c24efff8d04eff }

condition:
	$a0
}

        
