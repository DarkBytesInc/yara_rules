rule Win_Ircbot_Lazirc_4
{
strings:
	$a0 = { 7a7956785d2d5b4952432d57 }
	$a1 = { 626c65626565205669612073652066 }

condition:
	$a0 and $a1
}

        
