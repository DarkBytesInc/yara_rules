rule Doc_Trojan_Garble_1
{
strings:
	$a0 = { 9b85a591c1ad203d2043687228417363284d696428a296c22c2096b394888499bc97932c20312929202d20285269676874288890b4a39c8db6c6a9882e6c696e657328322c2031292c204c656e288890b4a39c8db6c6a9882e6c696e657328322c20312929202d20312929202d2028496e7428282834202a204c65 }

condition:
	$a0
}

        