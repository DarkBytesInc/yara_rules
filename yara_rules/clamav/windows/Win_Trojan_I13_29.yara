rule Win_Trojan_I13_29
{
strings:
	$a0 = { 81ed0300b84d41cd213d524f745006b82135cd212e8c8692022e899e90028cd8488ec026a103002d4600931e07b44a }

condition:
	$a0
}

        
