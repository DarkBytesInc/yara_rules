rule Doc_Trojan_FootPrint_3
{
strings:
	$a0 = { 4b696c6c2022633a5c666f6f747072696e742e24243f22 }
	$a1 = { 747474203d206174706c2e46756c6c4e616d65 }

condition:
	$a0 and $a1
}

        
