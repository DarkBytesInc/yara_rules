rule Win_Downloader_1126_1
{
strings:
	$a0 = { f8ebb2428d54275b59f07529c0bbb9b0abc0a43bcd93a2c1f8b335a01bcc06780070c62cdf2c4b77a0bf73b1e8b58ac4b975a38864cd802dc3f8f08a2d18b1aaf8efcd045bb01fc2adcb59fcc4c80dccc8f8f6ce272b6ac1b7655540 }

condition:
	$a0
}

        
