rule Win_Trojan_Bancos_128
{
strings:
	$a0 = { 2cec63630c0a053324c11030c1cea0086e65741495f3001e7573756172696f18022c94ae54311cf82984db0b2c1eb0e131203424def18ec73528362cec78c73b373038343938070fdd2cec31303c3140873ef4a132443448354c431ffad0365037543858d08777e8395c3230603164e8431ffa3268336c34f4a10f7d7035743678efd0873e377c388039843ef4a10f333288338c34 }

condition:
	$a0
}

        