rule Win_Trojan_MasterParadise_3
{
strings:
	$a0 = { ff180000004d61737465722773205061726164697365204167656e742000000000ffffffff0b00000054466f72 }

condition:
	$a0
}

        
