rule Win_Trojan_Hupigon_351
{
strings:
	$a0 = { 6ad460d7fc762a5253c197012426a8c957f4b961fe86a8792ab93aa1aeba1ad927fb150962a5f4d33339cc48ba601c98174bbac08f4b450913191aa1c45922139e20dac369824cee8ad66c96e2ad240e0530e01aaaf2d20f11e2747c7f95135c56df740711cca71d16ff60fcca2e664f71bcc5431ecc5e6bdabff15d3c4ebf983724685905751c189b6a05f44d7c1987e609a9ae1d68 }

condition:
	$a0
}

        