rule Win_Trojan_VKit_7
{
strings:
	$a0 = { 5d90909081ed0601e84f00b82435cd21899e78018c867a01b4258d963d01cd210e07b4098d964001cd21b82425 }

condition:
	$a0
}

        
