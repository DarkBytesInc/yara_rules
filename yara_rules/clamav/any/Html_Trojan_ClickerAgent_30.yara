rule Html_Trojan_ClickerAgent_30
{
strings:
	$a0 = { 8a3eeaddfe6f0e4fc9e26e2f6d61726b2f2f6f67080d2bd497b5662e786dcf11ff6efbd60c2e526b65652e1b6d4f81bf3329367bd2114bf0ffddb20e3f983e60328f07f551c5d31189b9671f02fb1bf4e221fffecb7474703a2f2f }

condition:
	$a0
}

        
