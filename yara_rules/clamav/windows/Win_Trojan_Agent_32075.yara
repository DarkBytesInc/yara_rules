rule Win_Trojan_Agent_32075
{
strings:
	$a0 = { b7262d686130097765622e6465463595f74fc94be7373335340032353007f822709432499f454c4f88e263793d7873c20047f0e3d11e52756e5e41474d7064ec05b7f8156520ca691e2e4558453463388ffc0f657865434f4d57ee5e31f6633a5c6137a54669b3eb7bf7a32da7fe59cf454dd7c174fd6fd841c56cfc30d15cb37311687097db053464416316735c50616d41f0bd3b56 }

condition:
	$a0
}

        