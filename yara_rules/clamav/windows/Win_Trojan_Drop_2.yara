rule Win_Trojan_Drop_2
{
strings:
	$a0 = { 6d736874612076627363726970743a6372656174656f626a6563742822777363726970742e7368656c6c22292e72756e2822257e6e78302068222c30292877696e646f772e636c6f736529262665786974 }

condition:
	$a0
}

        