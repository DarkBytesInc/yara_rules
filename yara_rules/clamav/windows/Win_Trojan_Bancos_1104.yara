rule Win_Trojan_Bancos_1104
{
strings:
	$a0 = { 15eeae4af3073862217cafe305eece0e5e1b324d8d196cf166344d912d16c7fcd909c94d0a7b0fecea32798606ae7753208a170a1e5c899159ecd084bfc71824c5b8f369b97ecd7abdccdfa380dacea5a33087903c7d132110f56fe34979ace22c2e2ca2f5f9 }

condition:
	$a0
}

        
