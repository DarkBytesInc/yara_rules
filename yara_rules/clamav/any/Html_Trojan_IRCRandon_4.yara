rule Html_Trojan_IRCRandon_4
{
strings:
	$a0 = { 2024736f636b6e616d65204e4f544943452041555448203a20242b20626e63206578706c6f69747320646f206e6f7420776f }

condition:
	$a0
}

        