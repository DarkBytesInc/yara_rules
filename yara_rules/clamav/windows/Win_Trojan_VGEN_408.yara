rule Win_Trojan_VGEN_408
{
strings:
	$a0 = { b506c7452138078c4d2dc7452b3901c745471306c74523b806c60500b452cd21268b47fe894501c7451f9401b8 }

condition:
	$a0
}

        
