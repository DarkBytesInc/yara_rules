rule Win_Downloader_Banload_399
{
strings:
	$a0 = { 950d0a2eb173c5665bb08833b7a8220cd36e9adc3894c774c79b82789f66eea53eac1f694b21d2503b6f586a32cf6244bf88109a32f37929f0a91b09f76ef4767252baeff9c4ffacefbe670b10661fba451fbffd1f74a4b1f3ed68d16e44c6814e61ff3c1e934e7b6a }

condition:
	$a0
}

        
