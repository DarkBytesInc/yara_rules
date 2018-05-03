rule Win_Proxy_Agent_34827
{
strings:
	$a0 = { 7507392cdcf289e0a1bc8bdba14de6417e16ce5d9a68bdef71ec5e524490ba731585cec0c670cbf060e5d5c18f26c4cb4e0b3e66c8797e616a7b6fcb80bcc881fcd1798270a9527cacd917c700dcda9bc7da1ede901178ad75c48f47171af996aae572f39b4e20b1ae75bd28c64ad093d2baede0a2c6df18a1e629 }

condition:
	$a0
}

        
