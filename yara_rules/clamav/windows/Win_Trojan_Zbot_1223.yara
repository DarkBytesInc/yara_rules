rule Win_Trojan_Zbot_1223
{
strings:
	$a0 = { e92800000000000c000000000000ad26ecb89b00c7c5000000000000970000fc16177e0000b3f100 }

condition:
	$a0
}

        
