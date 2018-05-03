rule Win_Ircbot_Madrox_2
{
strings:
	$a0 = { 4d417ff3dffe44524f5800002402005553455220257340676f6f676c65cfbf53f62e636f6d0d0d }

condition:
	$a0
}

        
