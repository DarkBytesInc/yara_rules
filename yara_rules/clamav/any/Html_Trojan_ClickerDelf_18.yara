rule Html_Trojan_ClickerDelf_18
{
strings:
	$a0 = { 2f8b7701022e6e696b6164d06d757a73c39c666f2f7cb87b702a657408632e4e6d6c5871b8a19b380a42bbcda22707ae484aeea54949 }

condition:
	$a0
}

        
