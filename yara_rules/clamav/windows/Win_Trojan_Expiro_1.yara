rule Win_Trojan_Expiro_1
{
strings:
	$a0 = { 60e8715c020061e9 }
	$a1 = { 596f7e5d63646e657d4665646d4b0008002073455474494d45520008007320160735 }

condition:
	$a0 and $a1
}

        
