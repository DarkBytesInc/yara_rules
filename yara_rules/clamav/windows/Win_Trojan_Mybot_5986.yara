rule Win_Trojan_Mybot_5986
{
strings:
	$a0 = { a5fceb54378a13d9f555ebbd330cda4b354e79f1fce0eaf26f33fe72c91d7a642a717ef1ede2ab3aebc2404c2fa56ac89bf7e7b784412524132374d11cc0f93755df658c652921e12f03cdc6c0f390e1b7e406ca53 }

condition:
	$a0
}

        
