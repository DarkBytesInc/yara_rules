rule Win_Ircbot_Mabra_2
{
strings:
	$a0 = { 46f66201c746f46701c746f28301c746f096018d46e61650b8aa001e50b90900e824058d468c16 }

condition:
	$a0
}

        
