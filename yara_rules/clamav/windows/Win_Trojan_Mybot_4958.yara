rule Win_Trojan_Mybot_4958
{
strings:
	$a0 = { d4b6c7812d948973874e00e7e4d2e3d5ad814efa4fab7b4406bc3a63f3c58a980f4350d26a2020a5e8ec35e675acdee018fa61b7863547fb03d473fd2059e77f8ea7427ac03203b54552a6919ea2 }

condition:
	$a0
}

        
