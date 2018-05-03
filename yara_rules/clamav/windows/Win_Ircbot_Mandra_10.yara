rule Win_Ircbot_Mandra_10
{
strings:
	$a0 = { 494e3a233a2f6463632073656e6420246e69636b20433a5c6d6972635c7365782e636f6d }

condition:
	$a0
}

        
