rule Unix_Worm_Coptic_1
{
strings:
	$a0 = { fc6fc0505249564d534700346d4d30fc44df30fe4552524f5200540bdb20052deb26b65973192bdb27cc441950494e47044f7d63dfb6d80d702a095041535390231d6119ff2022005c2530336f9e91616270416da1102f7614b5b6867b561d0c6e759bbe1f63ba0d7bcc051908366d64dd0a5b212cde6875b47965055d888218 }

condition:
	$a0
}

        