rule Win_Trojan_Trinoo_2
{
strings:
	$a0 = { 30742d4d696c6b2c20666a656172206d650a008d7426008dbc27000000004e75636c6561722057696e }

condition:
	$a0
}

        
