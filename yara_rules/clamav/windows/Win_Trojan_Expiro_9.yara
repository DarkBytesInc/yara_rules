rule Win_Trojan_Expiro_9
{
strings:
	$a0 = { 60e87170020061e9 }
	$a1 = { b801000000c331c0408b4c2404f7410406000000740f8b4424088b5424108902b803000000c3 }

condition:
	$a0 and $a1
}

        
