rule Win_Spyware_Delf_1954
{
strings:
	$a0 = { 9a7d0f5c5455daff9d990b0c38caa0a8a4a8e48e25a205a2090ee4f067105164e49f88a0b1c18446eac2bd6a053aecc8c6e5c42ebbafeddb7eea7d7ffa66bb6deb6f5f767393fe6c0d0cf127dd427415c592d25aec5a4dcaeaa0e4fc9ee7dc33039665fdfcc87ccf3d7f9e73ce739ef39ce7fcb9e7f27a13a70948deba }

condition:
	$a0
}

        
