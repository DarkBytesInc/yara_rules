rule Win_Trojan_Hupigon_174
{
strings:
	$a0 = { 1df94a7cfc111e32603bd93d811300fc7f02ded4d82e99be6b65e998cdc1bc4dd1b65bdca53a074bba6cd84ec3a016a526a8abbec6543e5de8650ba2a4ccfccdc9373583022703d2b6b92763cbf6892bc4b0e935fadbe184efc3fae93976c7581449e9f9b14f6e6521 }

condition:
	$a0
}

        
