rule Doc_Trojan_Fool_7
{
strings:
	$a0 = { 44726f7050617468203d202822433a5c57616c7275532e64727622290d }
	$a1 = { 526567697374657265644f776e65722229203d202257616c727553 }

condition:
	$a0 and $a1
}

        