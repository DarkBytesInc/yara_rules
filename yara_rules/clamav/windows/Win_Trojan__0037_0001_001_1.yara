rule Win_Trojan__0037_0001_001_1
{
strings:
	$a0 = { 0402b80042e82b008d96ff01b90500b440cd21fe8606025a59b80157cd21b43ecd2180be060201 }

condition:
	$a0
}

        
