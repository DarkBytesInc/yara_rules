rule Win_Trojan_Bancos_596
{
strings:
	$a0 = { a4a5f743e78bc378652b9fd5f3e072e4ce1d62ed775fd5a9e222f21dff7665c280ec03b21769a997ff2bb4a8ccd9aceed5fd2caceb2fb56e8a031f5d4c1516b42de81525916ba7b00ec8554cbd24476945aca2a58b8c0b25f09f38754be66f3cd0da6f017c7a817eaf2d36437842b30250ef159ef71dfc4adc73af6c9b8d6c77ed7cff379b160be6105a92751c1886e8c78a12234c4b }

condition:
	$a0
}

        