rule Win_Trojan_Timid_8
{
strings:
	$a0 = { e800005f81ef1602e82600b41aba8000cd21be000181c733025687f7a5a5a4c390909090900000000000000000000000 }

condition:
	$a0
}

        