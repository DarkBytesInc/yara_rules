rule Win_Trojan_Screamer_2
{
strings:
	$a0 = { e800005db430cd213c02765b33c048cd210bc074521e33c08ed8ff0e1304c51e84002e899ed3002e8c9ed5008cc34b8edb812e03008000a112002d8000a3 }

condition:
	$a0
}

        
