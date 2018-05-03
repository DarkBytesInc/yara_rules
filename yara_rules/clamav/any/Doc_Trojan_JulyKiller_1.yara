rule Doc_Trojan_JulyKiller_1
{
strings:
	$a0 = { 4d7367426f782022c4fab5c4204f666669636520c8edbcfed2d1beadb3acb9fdcab9d3c3c6dacfde2cc7ebd3ebced2c3c7c1aacfb53a202020202020202022202b2043687228313329202b205f }

condition:
	$a0
}

        
