rule Win_Trojan_SdBot_4053
{
strings:
	$a0 = { 65e178a529dfd90724c9bc769228f54ab67e2f533ce1d7b5bbcd48250a53599a5f8d08f0d80f0d64b0d0a40e202bd61e7819ff8e7fb22b6e8c390c7e1bf40586481543a7f8c3af9db0e8996df9de4f2aad66f170de3c }

condition:
	$a0
}

        
