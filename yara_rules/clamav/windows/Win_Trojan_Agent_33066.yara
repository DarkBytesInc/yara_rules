rule Win_Trojan_Agent_33066
{
strings:
	$a0 = { 021cefd937309af046e0a10b904078eb95111789013f002323ff2ffcff18b34128388835cb57dd41114476564908fe26dc857b181e9c72ffff7f812acdbb62aed2075cbe68b88fbc7bd8 }

condition:
	$a0
}

        
