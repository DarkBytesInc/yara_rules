rule Win_Trojan__0523_0001_000_1
{
strings:
	$a0 = { b8024233c999cd21b4408d960301b92202cd21b801578b8e80038b968203cd21b43ecd21b5008a }

condition:
	$a0
}

        
