rule Win_Trojan_Spambot_233
{
strings:
	$a0 = { d3def8ffffff5def805aa1d83698e6361da9e9574e66a0045ae6615c44fefae102ccbbffffbf06bd731c95d2e23f189386208ed4d06ca0252983ebffffffff6c2d0d51216b8cbfb10173abde9e769a8638dadea98bc0c5e81a85beb6a28a3dffffffff4a6900798646545f13bb17 }

condition:
	$a0
}

        
