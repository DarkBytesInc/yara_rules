rule Win_Trojan_Mybot_5290
{
strings:
	$a0 = { d34625c89ea7f2f6a4c658167dc18ed6c55dee6e2c5f5b20abf78a8b653543fc538dd08ebaf97114b9566741d68610cddae5ee6322cdb47e777f7c06defc604f3fe7d851ff6252c3016358146c4d8a5385574ca755e82354647433fe214213060c81f18a29de83c72579080977bf378e349a941318fabab402fa441bb5b4b42eb1c7aad425da5a1368e6 }

condition:
	$a0
}

        