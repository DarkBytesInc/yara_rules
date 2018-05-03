rule Doc_Dropper_Agent_1383204
{
strings:
	$a0 = { 433a5c4161[0-26]433a5c55736572735c4d5c417070446174615c4c6f63616c5c54656d705c[0-6]2e657865 }

condition:
	$a0
}

        
