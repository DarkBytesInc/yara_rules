rule Win_Trojan_Soldier_7
{
strings:
	$a0 = { 6a003ec7b4f1e6d03fd06ef80dda09f4acd7e6785ba7dd08d0d0eb6cba4aa7b681ca844b336a368de8d1eb2ddcd3998514dfe37d1e00a61b208dc148ce4645ac2ba5c4a6df35306900f593e79188d5778eb6f32f20e5541153b248 }

condition:
	$a0
}

        
