rule Html_Trojan_ZlobGeneric_1
{
strings:
	$a0 = { 60be00b041008dbe0060feff5789e58d9c2480c1ffff31c05039dc75fb464653 }
	$a1 = { cbcbcaffe6e5e4ff6b6b6bd7636263117472700788868458d1d0d0f4ffffffffbcbbbaffb7b6b5ff797979a329272929000000000000000093908e6ccac7c7ffb9b6b4ffbbb9b6ff8784839e00000000000000001211176a28272afb575556ffb2afaeffbebcbbffe0dfdeffa2a09fff }

condition:
	$a0 and $a1
}

        
