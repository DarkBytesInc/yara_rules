rule Win_Trojan_IRCBot_628
{
strings:
	$a0 = { 37286ae32df6e4a6e034852c8c16f72855742ec72352fd789251697ce78f0f30f0723993ecc605f2f28e3d60e17cb638be28cf547925b2da18ccd50141fd83ef80e7459c3e0db6aa20bd2991cbf1 }

condition:
	$a0
}

        
