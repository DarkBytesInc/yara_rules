rule Win_Trojan_Fakeav_42
{
strings:
	$a0 = { 5589e581ec980100008d059687430089188d05d9884300505b8933578f055887 }

condition:
	$a0
}

        
