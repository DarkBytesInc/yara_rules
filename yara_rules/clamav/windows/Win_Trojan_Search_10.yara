rule Win_Trojan_Search_10
{
strings:
	$a0 = { 01018b5e0081c30301bd00018a57fc8856008a57fd8856018a57fe88560253e906002a2e434f4d00b44e5a5283c223 }

condition:
	$a0
}

        
