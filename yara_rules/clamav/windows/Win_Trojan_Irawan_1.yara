rule Win_Trojan_Irawan_1
{
strings:
	$a0 = { 64366a204d6163726f536869656c642c206d6163726f2076697275732072656d6f766572641a1b }

condition:
	$a0
}

        
