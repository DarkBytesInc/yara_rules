rule Win_Trojan_Redirector_5
{
strings:
	$a0 = { 646f63756d656e742e6c6f636174696f6e3d27687474703a2f2f[0-13]2f73686f777468726561642e7068703f743d }

condition:
	$a0
}

        
