rule Win_Ircbot_Desire_1
{
strings:
	$a0 = { 100000001e05000030050000160000006005000020 }

condition:
	$a0
}

        
