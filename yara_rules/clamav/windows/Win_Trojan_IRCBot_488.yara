rule Win_Trojan_IRCBot_488
{
strings:
	$a0 = { 0c7e71e674278fe69bc55fa0fdeb5dc4902864b500e41b3f13954d0c1010ec39d8e6f6f4db8bdc73ac6dc98be4ec99b6ed22f6928c2323960886eee42dc9fea9521bd9bc92e620c81e0bdf6cd0e182790f4e772f07dc3728401c7758a17b3055019db5f292414afeab13c8b62c6eb1a7532c3e05cebeb68432c0e7fa7eea970e9b64e5b44962edfa4320262e8aacdfcbc919c6ecbdc6 }

condition:
	$a0
}

        