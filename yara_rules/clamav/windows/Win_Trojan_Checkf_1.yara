rule Win_Trojan_Checkf_1
{
strings:
	$a0 = { 5267090273ca020c6a094368656b576172657a645267d6806c0000645267c2806725800506076a083a4368656b46756b126a094175746f436c6f7365126c060064 }

condition:
	$a0
}

        