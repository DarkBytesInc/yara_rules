rule Win_Trojan_Trojan_151
{
strings:
	$a0 = { e9000021e800005d81ed07018d96e601b41acd21bf0001578db6de01a5a5eb1033c08bd88bc8be64008bf8c3b44feb09b44eb907008d96d801cd2172e381be09024e44 }

condition:
	$a0
}

        
