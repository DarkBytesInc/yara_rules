rule Win_Trojan_Spambot_155
{
strings:
	$a0 = { d4a6d858d25057dc1df0e7cc27ffffff7fc15145483cec03141c8486d508a48f00f31107d11dc996a4938a690ef6ffffffe043e81a11ae95a465dfeb6a796f2bffb463786f45454b2ae6a732ffffffffe14471dc240bf5731b21ef6c792da5301cfbe23d5f4f1b92e2143da3137e }

condition:
	$a0
}

        
