rule Win_Worm_VB_658
{
strings:
	$a0 = { 65006e0059006f007500720053006f0075006c00000000000e0000006100760070002e00650078006500000018000000010092000100000000000000000000000c00000000000000100000006b0069006c006c002e006200 }

condition:
	$a0
}

        