rule Win_Trojan_W_270
{
strings:
	$a0 = { e08b855717400050b978563412ff95e616400089855317400083f8ff7501c36a208b }

condition:
	$a0
}

        
