rule Win_Trojan_Small_3904
{
strings:
	$a0 = { 6a30ea52a46d0ad5569bef7cd32467c0d114b9630794736909446fc0c9d4b723d6a03ff1c9fcbfb39b6606ecc234d3933c4cadeaba34c7e9ba34bfe9ba34c3d5506f0dbe79d00ae40a2172ec8a34db9b0c86b418622eef609c66 }

condition:
	$a0
}

        
