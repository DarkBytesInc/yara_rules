rule Win_Trojan_SdBot_3632
{
strings:
	$a0 = { 7830a85c493a83c226f384afb88605adb91140a6aca7d3bf1a2e9aa854427b736a1cf96ed5e0ec9ea71f8f1a888bf7a5a85443ce6992df45933341eee6b6f2eed1245031eb0016434a0c83a35564 }

condition:
	$a0
}

        
