rule Win_Trojan_Agent_35099
{
strings:
	$a0 = { e3859d127ff50c4e58713ce2ef110ed27c35d206adc6add29d80bdfdfb0df49e0cfbd67bb627d4f738b481d4869aa41f97bde9bc24c6a604515b14c2fa0515f35ab1a0eae1cf5a4c6b02d21bf3f835340e4ba3c8eea0504c054f56118910cc43561a18d2 }

condition:
	$a0
}

        
