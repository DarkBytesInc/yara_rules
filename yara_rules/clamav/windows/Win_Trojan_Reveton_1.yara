rule Win_Trojan_Reveton_1
{
strings:
	$a0 = { 483a5c6f6d383676653477645c6d6e6b75626435786463675c6c6f39386a797665347865792e704462 }

condition:
	$a0
}

        
