rule Win_Trojan_Eumel_30
{
strings:
	$a0 = { 0200c5005d81ed0e018db62d01568bfe8b960e01b9b202ac32c2d1caaa42e2f7c37d62c8a04b51c815b6987806c8d72f0573b631a50e09f9a7a736dbaf13928856c6d73ca80cc524b7 }

condition:
	$a0
}

        
