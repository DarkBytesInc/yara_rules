rule Win_Trojan_I13_17
{
strings:
	$a0 = { 81ed0300b8424dcd213d4858745006b82135cd212e899ee6002e8c86e8008cd8488ec026a103002d2b00931e07b44a }

condition:
	$a0
}

        
