rule Html_Trojan_Fraudpack3661_1
{
strings:
	$a0 = { feffff31d23195d0feffff219574feffff21c2239564ffffff039528feffff31d0198504feffff31d0ff8d3cfeffffff8528ffffff199574feffff29954cffffff81c00009000009d0e8332c0000ba8a0000001b95c4feffff2355bc31ca29ca119570fe }

condition:
	$a0
}

        
