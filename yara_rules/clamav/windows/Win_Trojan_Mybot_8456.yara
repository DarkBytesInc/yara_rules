rule Win_Trojan_Mybot_8456
{
strings:
	$a0 = { 0faf058503c6d40821e19e8b842e4ff6c1822f0f447f3f7403f6f7223018eb4d2804b894338d751e1442ee3ee08b83e25e02ea0aa2fcbf8f807737461c2a39863476253da3ec2522f30b00fcffeb108ad160805cf6 }

condition:
	$a0
}

        