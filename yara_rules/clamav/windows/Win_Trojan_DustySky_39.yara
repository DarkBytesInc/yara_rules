rule Win_Trojan_DustySky_39
{
strings:
	$a0 = { 623a5c576f726c645c494c5c576f726b696e6720546f6f6c735c323031352d31312d3134204e654420566572203853536c20536f636b73202d203136372e3136302e33362e3134202d2068747470735c4e654420576f726d5c6f626a5c7838365c52656c656173655c4d757369634c6f67732e706462 }

condition:
	$a0
}

        