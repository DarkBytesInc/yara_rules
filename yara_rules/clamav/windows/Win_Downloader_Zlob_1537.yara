rule Win_Downloader_Zlob_1537
{
strings:
	$a0 = { 29663434aecd94f9aa096b2dadb239e6138ef7d8f5e2d6d32cc8f7230dae2b96ae7f7c5f2677515bb4e26109e784df6160c155447fe0214e095effd7ae8287ebacbfa64cf5688058bc3918458a61c1abb6e5e0d29ac76db85df574 }

condition:
	$a0
}

        
