rule Win_Adware_Lop_170
{
strings:
	$a0 = { 80dee462a5a2124b2f45ecc613aec99468d4d8007e2c534da4f667a3efb9ddd21b4ff519548539037d9daed8ef756e7f69766e188df4f83190a767a611fdc8b6f2b5b23e7e5dad42cb7092fbd2fce1eafb5c98530c8a637b2d9f6988798c1321dfd6 }

condition:
	$a0
}

        
