rule Win_Trojan_W_170
{
strings:
	$a0 = { 6800104000c36066b8023dff1772e6938bd633c9b504b43fff178b423c03c28bf86a205947803f427402ebf847578bf5 }

condition:
	$a0
}

        
