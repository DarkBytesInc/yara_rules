rule Win_Trojan_Spambot_206
{
strings:
	$a0 = { c965344ca86fffffffffc0d599154a04df11deaeacccc83c3c9521b1cbb6e4577782efbe4e4acbf1a56ffaffffffaf807ae6c0adb7ae79b58a57b2a3c7b6828062df3fd5536431eeeb2b4affffff9bb152d6a7bbc40a6edb0ee69e876833e9e8da87a1328ee0ffffffffe901f643 }

condition:
	$a0
}

        
