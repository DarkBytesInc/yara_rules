rule Win_Spyware_Banker_963
{
strings:
	$a0 = { a5ba0ccecfce5070c4f5426bae97da65bcf6d087ea52eb9eac3272a24fe3b4dece2e5b14cd6c379573fe2bd6ac74b250bccecf00d413d5940e93a33a542ee8c0ad21a16c151ef6d5f4bd2e5fd9abcd7d6a4abc1d857c986d8d7b0633a23005d65546aa6a5ce0be2d4f1a4ead8dfe405a56355008691ee7b424fc0740be437e15 }

condition:
	$a0
}

        
