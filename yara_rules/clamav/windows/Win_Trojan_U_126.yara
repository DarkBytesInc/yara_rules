rule Win_Trojan_U_126
{
strings:
	$a0 = { 31ed5e89e183e4f0505452685c8c04086898850408515668b08a0408e81ffffffff490905589e55350e8000000005b81c3f21600008b836000000085c07402ffd08b5dfcc9c390909090909090909090558b15189e040889e583ec0885d275498b15149e04088b0285c0741a8d7426008d4204a3149e0408ff128b15149e04088b0a85c975eab81086040885c0741083ec0c681c9e0408e864feffff83c410b801000000a3189e040889ec5dc38d76005589e583ec0889ec5dc38db6000000005589e5b8c085040883ec0885c0741583ec0868389f0408681c9e0408e8cffdffff83c41089ec5dc3908db426000000005589e583ec0889ec5dc390909090909055a1349f040889e583ec0c8b55085268a08c040850e8b6fdffff89ec5dc390905589e552528b4508505068208d0408a1349f040850e896fdffff83c410c74508ffffffff89ec5de964feffff8d7426005589e5565383ec14c745f40100000068ff0000006a036a02e863feffff89c383c41083fbff751983ec0c688b8d0408e83cfdffff891c24e824feffff8d742600 }

condition:
	$a0
}

        