rule Win_Trojan_SdBot_1614
{
strings:
	$a0 = { 11931c5b20ae31b271b9360e457933d0ac257f2978eef6aa25ca622b722dd51f266856704bc42b554585825e1bae8cee41a79bc6a17c74ed7b5c70aa6d38c29e7a7df3c268d4 }

condition:
	$a0
}

        
