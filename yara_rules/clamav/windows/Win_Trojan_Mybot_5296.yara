rule Win_Trojan_Mybot_5296
{
strings:
	$a0 = { a3c10ab4a0325898f366d5fca4fe2b4843310369d9649f33676e0d3d49f53738b140b1171479528bb2cbdc611d84f47068511a8acd9769d6edca9d516842a59d658914efb502ff41fb9a5989da09edf9139a8cc88c2a6dbe7e609613bfefae4850810244187ad14b6835252a877a0a0a6fe6aff79dbcc3ac165f796959c022d01b538fdf }

condition:
	$a0
}

        