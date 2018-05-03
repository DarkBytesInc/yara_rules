rule Html_Trojan_ClickerSmall_98
{
strings:
	$a0 = { 83ec10b9080000008bd4b8141c40006a0133ff890a8b4ddc6a6856894a048b0e897de88942088b45e489420cff91fc020000 }

condition:
	$a0
}

        
