rule Win_Spyware_Banker_1592
{
strings:
	$a0 = { f4ecbedf050a5f5165199d6a83c5cfae3e582d24c8fbf3d82144c6e0d7a1aac3f927ae3921ec5e2646bd6eb2b68f26afbcf71747e659a926dd7647e8ad726aced6c2cb85cbbca74b7dba800eb6da74eb52f108c14ac0b7da1b3fc77abfe93efa2c67f0a7aa5f800edf04cd36da020934e5648ee59b5d9b774407cc54d8d2fe32 }

condition:
	$a0
}

        
