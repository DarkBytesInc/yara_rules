rule Win_Trojan__0198_0003_000_1
{
strings:
	$a0 = { 3e03004d740de897ffba6600b90300b440cd215a5824e09141b8015731069000cd21b43ecd211f }

condition:
	$a0
}

        
