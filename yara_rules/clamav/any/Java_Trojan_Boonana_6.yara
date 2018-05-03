rule Java_Trojan_Boonana_6
{
strings:
	$a0 = { 69612f636c61737370726f746563742f61 }
	$a1 = { 69612f636c61737370726f746563742f436c61737350726f74656374 }

condition:
	$a0 and $a1
}

        
