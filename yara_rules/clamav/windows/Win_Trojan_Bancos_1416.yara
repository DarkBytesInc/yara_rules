rule Win_Trojan_Bancos_1416
{
strings:
	$a0 = { 227ada3e9fe8b639e5639f0a82ca0273ce8a45a120d8ea7eb18fdd692e549b87c4b011c8bbf5ccd7589e692057c0914b78a1cfc9c2ac9ac6fc897e9ccac13b4a4c89c099aa62896541b8fc5e5d36498e9467e1192eef85bd2206 }

condition:
	$a0
}

        
