rule Win_Trojan_VGEN_143
{
strings:
	$a0 = { e9cc049053506f564952817cfb2e457507817cfd5845746fbfc500b903002e8b36dd075183c708b10857f3a674065f }

condition:
	$a0
}

        
