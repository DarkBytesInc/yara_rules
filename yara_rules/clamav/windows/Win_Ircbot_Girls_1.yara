rule Win_Ircbot_Girls_1
{
strings:
	$a0 = { 4769726c73005a6970576f726d00007a6970576f726d }

condition:
	$a0
}

        
