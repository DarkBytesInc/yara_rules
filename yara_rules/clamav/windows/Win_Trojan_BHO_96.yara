rule Win_Trojan_BHO_96
{
strings:
	$a0 = { 5c786d6c32753332682e646c6c[0-1]7265677376723332002f73[0-2]5c786d6c32753332682e646c6c }

condition:
	$a0
}

        
