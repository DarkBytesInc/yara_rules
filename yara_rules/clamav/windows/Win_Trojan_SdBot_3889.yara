rule Win_Trojan_SdBot_3889
{
strings:
	$a0 = { 70bb2ce6f1a008cbf33b2948a4eb007c277dd2de355d9695867e7abd9abe8cfdd7e6bf647baad1e675df092ea3e97670e213665223fe7bfd79a9eeda2624222ee363fc7569a5a6add6b4767e193ce27581ed333c47d38b2f1a3755c2 }

condition:
	$a0
}

        
