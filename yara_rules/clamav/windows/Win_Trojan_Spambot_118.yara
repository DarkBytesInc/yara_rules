rule Win_Trojan_Spambot_118
{
strings:
	$a0 = { aee5ffffffff6a78e31b6790de77aea0ca430571e0d2fcabacb79163f07f3c035d31b96b90dbffffffffc3110a5627d1ca07a6d956e137890d8acb2cc4cf9eb6ff1fb32eb421c7a8214affffffff86b3aac692dc88fcb5620da535ac675f5c957484434b450cc04979160ee54f9e }

condition:
	$a0
}

        
