rule Win_Trojan_Renomb_1
{
strings:
	$a0 = { 68fcb04000ff15505343008945b0c745a808000000ba74a140008d4dd4ff15e4544300ba14a140008d4dd8ff15e4544300 }

condition:
	$a0
}

        
