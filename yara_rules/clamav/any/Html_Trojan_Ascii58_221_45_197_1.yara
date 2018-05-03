rule Html_Trojan_Ascii58_221_45_197_1
{
strings:
	$a0 = { 35382e3232312e34352e313937 }

condition:
	$a0
}

        
