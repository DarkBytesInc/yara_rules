rule Win_Trojan_SdBot_4029
{
strings:
	$a0 = { a51143f0896ae38b235eaed982a4fca74698afa85a9e4fbd85e45c7efcd3a90d152d364d18d05eb877e8c4e56cfdacb1e17912843d65a99967b18164abc48544af874f7d5ad784bbd62dd18a7ce8d6be1c5629ce0292 }

condition:
	$a0
}

        
