rule Osx_Trojan_RSPlug_11
{
strings:
	$a0 = { 7461696c202d[2-4]2430[0-150]207c2075756465636f6465202d6f202f6465762f7374646f7574 }

condition:
	$a0
}

        
