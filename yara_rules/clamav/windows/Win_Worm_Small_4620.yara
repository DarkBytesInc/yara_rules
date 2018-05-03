rule Win_Worm_Small_4620
{
strings:
	$a0 = { 5c4f75746c6f6f6b20457870726573735c352e305c4d61696c[0-20]596f757246696c652e657865 }

condition:
	$a0
}

        
