rule Win_Trojan_Kool_1
{
strings:
	$a0 = { 666f722025256120696e20282a2e626174[0-27]633a5c5f6b6f306c206b6f306c206920252561 }

condition:
	$a0
}

        
