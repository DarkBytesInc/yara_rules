rule Win_Trojan_Delf_999
{
strings:
	$a0 = { ec7c0013112901009cd41a019c7c958dbb7d00002cf15aec2c54a3d59f7c9ac0eff8ab009c7c974fe8f79ab89e7c00cb112003009f7a958d4c620000690be4029f7cc60d9d7c00e8682500006bfb }

condition:
	$a0
}

        
