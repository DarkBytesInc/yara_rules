rule Unix_Worm_Slapper_1
{
strings:
	$a0 = { 82838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdce0e1e2e3e4e5e6e7e8e9eaebecedeeef }

condition:
	$a0
}

        
