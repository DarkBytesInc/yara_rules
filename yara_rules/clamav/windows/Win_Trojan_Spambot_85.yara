rule Win_Trojan_Spambot_85
{
strings:
	$a0 = { c6e0650085bf1f6d6ac5ae580639715d53cffc61d0fffffffe2ec2039590fad49b41510912d5dbfbd8cc6dde57832f4b803dd103ff6a2080ffff57eb193214812df0b984af59ea6116c3efffffff7ff1d1a48d835470387676644b27e5a5d64b74cf445e28b8fd30d871ff07ffaf }

condition:
	$a0
}

        
