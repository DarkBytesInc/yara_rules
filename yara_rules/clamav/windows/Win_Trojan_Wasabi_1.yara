rule Win_Trojan_Wasabi_1
{
strings:
	$a0 = { 6e742e696e736572746c696e657320382c20222e766972757370726f74656374696f6e203d206e22 }

condition:
	$a0
}

        
