rule Doc_Trojan_Nitro_1
{
strings:
	$a0 = { 4e6f726d2e436f64654d6f64756c652e4c696e657328312c203129203c3e2022275739372e4e6974726f67656e22 }
	$a1 = { 4465736372697074696f6e5c53797374656d5c43656e7472616c50726f636573736f725c30222c20224964656e7469666965722229203d20224e6974726f67656e22 }

condition:
	$a0 and $a1
}

        