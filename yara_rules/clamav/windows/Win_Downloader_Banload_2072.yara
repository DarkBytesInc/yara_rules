rule Win_Downloader_Banload_2072
{
strings:
	$a0 = { 2ae6f82edf538948e85fb357648dccf7abf8bd23ddc1ec156cff64d17dffa50b36ee92286d5a98fa1c65360e6baecc8211b057a919e68e213e178c35183886116dea106eb1e9f82f4a45c88775ecdc6a5fd1803926b968de5ec39235b44e0a1bc037d4729869dd9b6e1eebb9f8aadd9e2efbed }

condition:
	$a0
}

        
