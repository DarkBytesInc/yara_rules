rule Win_Dropper_Agent_34527
{
strings:
	$a0 = { 68b05340008d45fce8cce8ffff8bd0b9b8534000b800000080e803ffffff8d8d60ffffffba90534000b8c4534000e8c6fbffff8b9560ffffff8d45fce8ece6ffff538d45fce88fe8ffff8bd0b9b8534000b800000080e8c6feffff8d8d5cffffffba90534000b8f0534000e889fbffff }

condition:
	$a0
}

        
