rule Win_Trojan_Mybot_8459
{
strings:
	$a0 = { 988f9458b639a9eefea7512ff6aff02816ea86168e1e7248064f53356337f3f6c6181e3e7d16f8eda953004a6b3a5b6c5f9fc58ecfca3a2e2b92b6766072d7a66c8b8ff40820ae8be4b6ed6f98bfd23cb8290ab0b8 }

condition:
	$a0
}

        
