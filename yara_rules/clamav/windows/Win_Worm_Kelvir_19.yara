rule Win_Worm_Kelvir_19
{
strings:
	$a0 = { 61006c005c004b0065006c007600690072002d0032002d004f00 }
	$a1 = { 400068901e4000ff15ac104000c78544ffffffe4424000eb0ac78544ffffffe44240008b9544ff }

condition:
	$a0 and $a1
}

        
