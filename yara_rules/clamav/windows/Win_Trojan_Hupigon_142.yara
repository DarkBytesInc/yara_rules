rule Win_Trojan_Hupigon_142
{
strings:
	$a0 = { 349121866f60845c365e9179a18c0d2865f26d19a29072e9bbdf8c2a110a60142a5b8d5bd30c4f750b08ef87d071742b5606fd48cba9667a41a0336179186a28a60ad5dd3e6195d93c7cde38a483bec198032f9622acf6b539ea31fc1fa77af8d5b09ce5e44c171af4 }

condition:
	$a0
}

        