rule Win_Tool_XPUnlock_1
{
strings:
	$a0 = { 5800500055006e006c006f0063006b00650072[0-73]45006e0065007200670079 }

condition:
	$a0
}

        
