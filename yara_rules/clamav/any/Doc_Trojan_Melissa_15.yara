rule Doc_Trojan_Melissa_15
{
strings:
	$a0 = { 6224203d20686b3124202b20736d6f24202b20225c392e305c576f72645c22202b207365633124 }
	$a1 = { 546f492e436f64654d6f64756c652e496e736572744c696e65732042474e2c204e5449312e436f64654d6f64756c652e4c696e65732842474e2c203129 }

condition:
	$a0 and $a1
}

        