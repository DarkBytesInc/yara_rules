rule Win_Downloader_Banload_386
{
strings:
	$a0 = { 55a451e3d1030e625a8dd8e02929f129b2a1fb62c10c5608a779ba07923a0a6f6356e8632068b98b5c26afbb07bba09f5f106843e11e898853e4e9bf5a932ff4ad1b72026abaf42f0438a2e9e23fb5beac7eddf45d7bf1ff3cde5954781d0259bf7ada97f511dbd72b }

condition:
	$a0
}

        
