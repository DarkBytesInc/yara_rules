rule Win_Trojan_VGEN_667
{
strings:
	$a0 = { 0301b89945cd213d30507439fa33c08ed8832e1304018cc8488ed8812e030000042ea102002d00042ea302008e }

condition:
	$a0
}

        
