rule Win_Trojan_Bancos_1616
{
strings:
	$a0 = { 39ee0242b9dc5f03014707f2483eaf8cb093783530363129c0d3fcb3ce106e195c49e7451d2774429f687dcce59317c29cb6786c0786c947fa15022ba83af22655052210e7a4d79c250342af195f6c1aedde760369f51a22a63ea17f4305c3441c82b625191482209374ac8692210aa94018f26d7d28e59b12a9ae15ff6c6c20a46666d3f11cb2aa8b5ac3ef5e7beb189eb31a33c5a3 }

condition:
	$a0
}

        