rule Win_Trojan_FakeAV_195
{
strings:
	$a0 = { 558bec81ecdc000000ba84190001899540ffffffc78544ffffff00000000eb0f8b8544ffffff83c001898544ffffff81bd44ffffffb8000000731d8b8d40ffffff038d44ffffff8b9544ffffff8a0188841548ffffffebc88d8d30ffffff518b9574ffffff8b02ffd08d8d44ffffff516a008d9548ffffff528b45fc506a006a }

condition:
	$a0
}

        
