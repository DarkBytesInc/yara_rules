rule Win_Downloader_Banload_1018
{
strings:
	$a0 = { 8c1d5a94eec682627eea9d425ce0e1728c0b195527687fe242ccf8902d0074e5abc61aeb3124af93ee3bae330a694d0dfd5e69097197b103259a1dc4b1e82a54a953f37215cbaebb0ce05c9199eb0c7aa0f45b99f5952d30ba9b37481f945ae9dcec2fbf56c89a7b8f5f0eb1c0 }

condition:
	$a0
}

        
