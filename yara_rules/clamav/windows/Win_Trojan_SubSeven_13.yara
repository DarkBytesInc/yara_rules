rule Win_Trojan_SubSeven_13
{
strings:
	$a0 = { b3466f726f6d25614163746998b0585e334dedf7f16167ef3d2b16f83374680e9d55973a9116023255526c834450726e }

condition:
	$a0
}

        
