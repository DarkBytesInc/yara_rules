rule Win_Trojan_Spambot_186
{
strings:
	$a0 = { 183049ea5bb296aacd1b9daadf7d973643a08f39823b824980a3fbb85b07dad8fdffffff7fba942532b600e4da0727cfdec1e018b280b8943115ba9b4692ffc9e5ecffffffff6ff25818fe5c23e6d0976f2c45301a096bbad7528c1615d893e8f60001dc9fffffffff62ac52676a }

condition:
	$a0
}

        
