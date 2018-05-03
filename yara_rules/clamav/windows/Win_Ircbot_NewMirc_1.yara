rule Win_Ircbot_NewMirc_1
{
strings:
	$a0 = { 1f8b76028b0435c3ea938b0432c38904463deae975f4 }

condition:
	$a0
}

        
