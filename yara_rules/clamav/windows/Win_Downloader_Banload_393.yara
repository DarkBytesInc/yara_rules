rule Win_Downloader_Banload_393
{
strings:
	$a0 = { 55283952a1cb1466b5a6df4b3b8fc3ce9c3e9d5098a6b21c6fa0a1e567827a6ac4ed3a29f33513e512808ee278ef7ee35e122a24b2e5b390dfcfd9823804ab69289f20642e960bc13e4b1ea513ed2bbca291a6a079f4ecac42ddafa9196eb8ec373b0c21 }

condition:
	$a0
}

        
