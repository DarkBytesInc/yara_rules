rule Win_Trojan_Hupigon_1383
{
strings:
	$a0 = { 7927448ba93ddc0595794af1826e3676c2cc257d59f475c823de885dccc0f9790d83afd47184764d55b1eb8ce81e687d55967e9cc4ffa007baeee0f97c51d87edc490b6f92b5de1e6cd6616bdeec5d077c5cb34afc26f096115b67b67ca55abb9152ada1a09bfe17c7f50e0034b48fee44abbbc7ebed }

condition:
	$a0
}

        
