rule Win_Trojan_Hupigon_821
{
strings:
	$a0 = { 004826620ec940dded09a041764ab8f92ce6475f3c86f1e6bafa706895b3df6f7d26332546a89c27d26e209f5c78f5d62c0eef1f2016d9c672d8be40ac97c7bee36d5c11c86063718ae16b9a3388cdc6fb1dc2d0c0ff36a6269bab9ad37d49 }

condition:
	$a0
}

        
