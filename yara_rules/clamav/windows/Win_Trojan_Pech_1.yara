rule Win_Trojan_Pech_1
{
strings:
	$a0 = { 656368656e6b612e7368765589e5b800029a3005700181ec0002bf01010e57b83f0050bf58011e }

condition:
	$a0
}

        
