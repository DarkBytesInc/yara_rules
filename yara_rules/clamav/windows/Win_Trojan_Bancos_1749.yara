rule Win_Trojan_Bancos_1749
{
strings:
	$a0 = { 82d32b31f6ab1cea28322a2d02b5892c996468051cd1be38f4d4b03e52a1a0556170475fcf5fa02f184c11869fffd2ec5308be8bf164fa881c674c39fc9125547ce043e028dc }

condition:
	$a0
}

        
