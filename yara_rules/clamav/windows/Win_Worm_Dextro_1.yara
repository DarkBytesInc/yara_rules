rule Win_Worm_Dextro_1
{
strings:
	$a0 = { ea38c83730ffffffe60174617465282964657874726f6d6574686f727068616e0073d2b563ee0d0a20001e203d074b98ff7fd30d020307a0c3a6d6fdcb5244b2 }

condition:
	$a0
}

        