rule Win_Trojan_I13_13
{
strings:
	$a0 = { ed0301b83030cd213d40407503e99000b82135cd212e899e7f022e8c8681022e899e88022e8c868a021ec51e0600 }

condition:
	$a0
}

        
