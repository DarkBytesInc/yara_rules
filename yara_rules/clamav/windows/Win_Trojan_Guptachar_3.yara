rule Win_Trojan_Guptachar_3
{
strings:
	$a0 = { 74656d1b72792077656220657276efe65a6b026361142838302bbbfdbdb7430e6e65632d7f4775703b6368312d9b6c582c80 }

condition:
	$a0
}

        
