rule Win_Trojan_Agent_33387
{
strings:
	$a0 = { dd9aebb7fb588504e6c3e4811e59a243cd9ba82a4e2ee9991fc37fbd76d73ef0b08c5909149b1e3df9f5d656b8b7805e4f8b7a8ad8b800aa6a9a5cc7cb4ed419cd667c5c366653d4d6939ab90326d44d914adaa678f2becee4b61b8c }

condition:
	$a0
}

        
