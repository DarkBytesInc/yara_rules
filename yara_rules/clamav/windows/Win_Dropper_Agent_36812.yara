rule Win_Dropper_Agent_36812
{
strings:
	$a0 = { 5c00540065006d0070005c006300680038006c0030002e006500780065 }

condition:
	$a0
}

        
