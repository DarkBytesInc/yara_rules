rule Win_Trojan_I13_30
{
strings:
	$a0 = { ed0300b8293bcd213d503b745006b82135cd212e8c862e032e899e2c038cd8488ec026a103002d5900931e07b44a }

condition:
	$a0
}

        
