rule Doc_Trojan_WhiteIce_1
{
strings:
	$a0 = { 696e66656374646f63756d656e74[0-200]72756e626c61636b69636500 }

condition:
	$a0
}

        
