rule Win_Trojan_SdBot_3491
{
strings:
	$a0 = { c6fcfaafb6b45cde9f5841f40fd6f004c4b209bc5ac5d6400653c5f6c52bcd58959b78ec1f0468d895c6919101c9d4f6d746fb075bdb54df74a75ddc9deeaad93a75150eab2d28a786a79319cefcf7c4e6757a44bdd124c1e4a76a39af60ecdbd5a4b534e34e84d9942fb8a7b49f4129d07bbbc97b6c }

condition:
	$a0
}

        
