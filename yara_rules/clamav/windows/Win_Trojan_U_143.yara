rule Win_Trojan_U_143
{
strings:
	$a0 = { 31ed5e89e183e4f050545268cc87040868e083040851566810860408e887fffffff490905589e55350e8000000005b81c34e1400008b833800000085c07402ffd08b5dfcc9c390909090909090909090558b152499040889e583ec0885d275498b15209904088b0285c0741a8d7426008d4204a320990408ff128b15209904088b0a85c975eab84884040885c0741083ec0c6828990408e8ecfeffff83c410b801000000a32499040889ec5dc38d76005589e583ec0889ec5dc38db6000000005589e5b80884040883ec0885c0741583ec08681c9a04086828990408e867feffff83c41089ec5dc3908db426000000005589e583ec0889ec5dc390909090909055a1189a040889e583ec0c8b550852682088040850e85efeffff89ec5dc390905589e583ec0c8b55085268a0880408a1189a040850e83efeffff83c410c74508ffffffff89ec5de98cfeffff8d7426005589e557565383ec188b45088b5d0c8945f0c745ec0000000068bc880408e88dffffff8b135952e81cfeffff8b0b83c4108d14088d7aff897de839cf7622b02f }

condition:
	$a0
}

        