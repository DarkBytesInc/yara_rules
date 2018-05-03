rule Win_Ircbot_Mabra_3
{
strings:
	$a0 = { 3a02c746f25902c746f07802c746ee8b028d46e41650b8aa001e50b90900e8d0058d468616 }

condition:
	$a0
}

        
