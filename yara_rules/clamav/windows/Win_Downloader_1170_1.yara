rule Win_Downloader_1170_1
{
strings:
	$a0 = { 610a135aceab6c013dc4d5e2c2602b0b508e6c35cac5503bcf0f0a788af9bb6daa3bb2ed88d026b1d14dc9f6ed8d816a9f6dfa0cd1b11917416c958a0bd6eb6ec7641b4587c28d42d68e22cde7cbf6cbf61a95db0f84a173e2e577b2 }

condition:
	$a0
}

        
