rule Win_Trojan_Spambot_240
{
strings:
	$a0 = { 60597fe96d2d1eb07bffc3ffff7e612d6c3e98f0aaac47f8c468401129204d2d0dbe576a4bd7a1ffffffff4a2b87426bdcb688fc3d05e65a3f9b451f3074fdc3b47ff0244f8e76233506edffffffff4d4cf1a8aaaa187e9ff3a6b7355fb1407df9114814944786df8b99b1fc8865 }

condition:
	$a0
}

        
