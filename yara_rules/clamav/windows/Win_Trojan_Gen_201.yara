rule Win_Trojan_Gen_201
{
strings:
	$a0 = { 7d019a0000e3005589e5b800029a7c027d0181ec0002c606e40300c606700100c706e0030100eb04ff06e0038d }

condition:
	$a0
}

        
