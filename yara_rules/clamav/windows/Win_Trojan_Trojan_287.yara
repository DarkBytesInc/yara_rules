rule Win_Trojan_Trojan_287
{
strings:
	$a0 = { 9a000050005589e581ec00028dbe00ff1657bf00000e579aab012e00bf8e011e57b84f00509a2b035000803e8e010075 }

condition:
	$a0
}

        
