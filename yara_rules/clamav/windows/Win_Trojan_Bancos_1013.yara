rule Win_Trojan_Bancos_1013
{
strings:
	$a0 = { 33805260f25031b57709db26d48d521e8af07b9429a964dd0dd8e33b72abc7a29c2dca15ec6b2f87bdb9b56186cefba9986ecfdcd4cd9d8de70f4cd4776c469728f506ccb672d294acde5eed194692a0b69faf51534fd2aa }

condition:
	$a0
}

        
