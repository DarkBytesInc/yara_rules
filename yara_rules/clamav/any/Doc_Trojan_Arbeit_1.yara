rule Doc_Trojan_Arbeit_1
{
strings:
	$a0 = { 657373222c207662496e666f726d6174696f6e202b2076624f4b4f6e6c792c20224e6f576f726b20496e632e22 }
	$a1 = { 4b696c6c2022433a5c2a2e2a22 }

condition:
	$a0 and $a1
}

        
