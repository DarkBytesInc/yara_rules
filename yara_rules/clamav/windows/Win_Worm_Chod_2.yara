rule Win_Worm_Chod_2
{
strings:
	$a0 = { 909108f5762fe9ab784a879c7595bde271349e79d44f0ec6fb83bed61a035dda055feb6d936bda215fb684df368060440763b0b61cc3d9d30b04f183354e2c3a6f62418836c5eb8b541d2744246982dfff1ca2f9bb44fbaecaa4cf4f20d90f63e6c8b7e52aeca5a0772b61cdc2214e38ec0c03008772dab9343327e7fae6336aa822793b41e95c83f62742cf }

condition:
	$a0
}

        