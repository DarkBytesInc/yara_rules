rule Win_Trojan_Small_3951
{
strings:
	$a0 = { 31d25252bab8a74000ff1209c0752a89c281c2cb3ceaf381c23565560c8d8a3c050000520577d7afb12902ff0a31c083c20283c20239ca7eebbad6a74000ff12c3 }

condition:
	$a0
}

        
