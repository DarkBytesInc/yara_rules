rule Win_Downloader_822_1
{
strings:
	$a0 = { 7bbfa1bce5db17bde561b2d91a6ab7eb089d4335dbedf0b675e5c2b6a635163b1bd1653c9ed406a0b851c9e7f445a7c26c1b1bee0149b0f5afb76ed9b6e4b313aaede7d42be1d940d92e0b3da5c1bc2ba3b7db9bad9b4bbbcd72b6e505b23103b833f8b25c6e5dad37ca492aa25cb28b96b643904bf037a40c9d9ba1 }

condition:
	$a0
}

        
