rule Win_Trojan_Dtfanri_1
{
strings:
	$a0 = { 697265666f782e65786500ffffffff0c000000696578706c6f72652e65786500000000ffffffff0a0000006368726f6d652e6578650000ffffffff090000006f706572612e657865000000ffffffff130000004d6963726f736f66745c6e7464726c2e646c6c00ffffffff010000007c00000068d0070000e8c6f1ffffe889fdffffebefc38bc0 }

condition:
	$a0
}

        