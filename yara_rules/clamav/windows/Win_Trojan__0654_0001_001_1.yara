rule Win_Trojan__0654_0001_001_1
{
strings:
	$a0 = { 81c5d5008846018866028bd5b440b90300cd21b442b002b90000ba00005b53cd21bd9a008b4600 }

condition:
	$a0
}

        
