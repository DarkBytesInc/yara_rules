rule Win_Trojan_Small_3929
{
strings:
	$a0 = { d95ef17b06e681180e0e8dca025d5d64f158f17bf6f11bfe1f4e0e874bfa834bf25d853bbe1f4e0e5e834bfa5e661d0e0e2ef17bf6c94bf20a0e0e0ef1d83753fa7a2c8f73fac60e0e0e7a178f73fa9a0f0e0e018a200d0e0ec94bfe0f0e0e0ee72c0d0e0e834bf25d5e }

condition:
	$a0
}

        
