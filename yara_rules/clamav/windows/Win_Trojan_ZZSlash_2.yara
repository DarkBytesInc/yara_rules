rule Win_Trojan_ZZSlash_2
{
strings:
	$a0 = { 3bc0741ceb00db2dbc934a00ffffffffffffffff3d40ff5650726f7465637400e8a1da0400fd0dfa8ac58171e6a63a739aa33dc0ef2c47f2aa4461be3ee3b37740999dd31b7504f20525ea9c325e42cb477f02691171795a77d1e3bdad513b6fab5b50d1def81bcc1df15012de3433a6aa78ad9ece249f28546d76cb31bf00ef }

condition:
	$a0
}

        
