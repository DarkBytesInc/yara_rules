rule Win_Trojan_Spambot_217
{
strings:
	$a0 = { c148e701bf9eaa3ce7b4617ff4ffff1396ae732b413a22cfb841708f670cbbd21dd169c15d8e37a8ffffffe86f8b6209a789fc7d47f538444962956a466a7bdd7a8a83fd57723f01ffffbbabaa784d11a409df31880f23af3cb5d5fcb63cfff4ffff8700a501f3e3f987916fa269 }

condition:
	$a0
}

        
