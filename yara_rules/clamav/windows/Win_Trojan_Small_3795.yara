rule Win_Trojan_Small_3795
{
strings:
	$a0 = { 5dc1a4c56201d65eb525e72212d6923af62efc3bf534f097f898e7c58927e38df32c1db8a558f7429d60d976a09ca1f1e5db170427238eb9dc6242439ed592c5e3d11d49d0a79501d72a9eaea03f }

condition:
	$a0
}

        
