rule Win_Trojan_Spambot_241
{
strings:
	$a0 = { 56463d85d16e212be915838aaedcdde6fd6bb185e1fbd4ffffffffae321b0292eae5081cf3e4a603d1a74b348729c1437b3da439b8a874346c491187ff03fcc5d5a3ef6985c33e7f703406fc1bb336d1fcffffff37766bd9159189f1a6b0ccb7cc45c4c7cf00efa3d329d37baf0b }

condition:
	$a0
}

        
