rule Win_Trojan_Small_4528
{
strings:
	$a0 = { 8231ac054f37056b3fcc831a2f6f874b6f6f6f36cc871a2f6f36ace4629f1a2f6feaa61b7ece871a2f6fe263e73e3f87da9090903636ace42b4b6b60c02b4b673f0567907a777f2f6f3f907a7b7f2f6f }

condition:
	$a0
}

        
