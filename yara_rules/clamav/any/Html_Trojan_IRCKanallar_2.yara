rule Html_Trojan_IRCKanallar_2
{
strings:
	$a0 = { 6b616e616c6c6172[0-200]656d61696c616464722073656c6461[0-200]6b616e616c6b6f6e7573746d72 }

condition:
	$a0
}

        
