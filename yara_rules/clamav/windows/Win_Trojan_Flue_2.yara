rule Win_Trojan_Flue_2
{
strings:
	$a0 = { 86e0e440a3a205be1601e88f04e90100c3e88404e800005d81ed1901eb0181e4210c02e621b90300bf0001578db65204fcf3a4b44732d28db6ae04cd21b4 }

condition:
	$a0
}

        
