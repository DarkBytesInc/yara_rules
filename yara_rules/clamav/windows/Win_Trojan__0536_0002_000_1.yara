rule Win_Trojan__0536_0002_000_1
{
strings:
	$a0 = { 4515000026c745170000b440b91a00ba600dcd218a0eb10626884d04e81a00b43ecd210e1fc516b2 }

condition:
	$a0
}

        
