rule Win_Worm_Banload_2102
{
strings:
	$a0 = { 20757365722052656d6f20313233343536202f61646420006e65742e657865006f70656e00000000ffffffff27000000206c6f63616c67726f7570202241646d696e6973747261646f726573222052656d6f202f61646400558bec6a006a006a }

condition:
	$a0
}

        