rule Win_Trojan_Jacktron_1
{
strings:
	$a0 = { f8db56e8416729656e766f7965fb8fad6dff55706c6f61642074326d2b26732377fb39ba3a174c25434f754a72742b357eeeb213462c51546f356beeadbb5220 }

condition:
	$a0
}

        
