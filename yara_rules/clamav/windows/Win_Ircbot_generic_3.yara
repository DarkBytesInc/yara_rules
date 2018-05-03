rule Win_Ircbot_generic_3
{
strings:
	$a0 = { 5c646d73657475702e6578650d0a6e333d202020207d0d0a6e343d20207d0d0a6e353d6f6e20313a544558543a676f61 }

condition:
	$a0
}

        
