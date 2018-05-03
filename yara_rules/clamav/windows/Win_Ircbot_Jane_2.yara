rule Win_Ircbot_Jane_2
{
strings:
	$a0 = { dd924c7fb390bf34393df3374996dc690cf1516e1a7c68c47614cb19f94eb2db18e6a31d590b283b2a0c25771847b1a3 }

condition:
	$a0
}

        
