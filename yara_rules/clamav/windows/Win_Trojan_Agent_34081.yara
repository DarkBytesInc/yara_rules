rule Win_Trojan_Agent_34081
{
strings:
	$a0 = { 6feb375da2efd68d62f7d2b0ce546da15df45d4310ba16ccd9400c910574e545efeef1f3f8bd5271a837f0b93d198e5c625a9465fb6adc5727e4a929758a83d9ca6fa6967ac9d51414567f930954681e774786b0e8d03f4babf1b69914688c19885f4a53f9afb9fcb4a388b691e2c086483ba2b45fb3cd738ac4dfde5029d220f728ceea0de9e9ba1e48c523 }

condition:
	$a0
}

        