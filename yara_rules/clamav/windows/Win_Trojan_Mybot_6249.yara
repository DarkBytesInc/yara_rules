rule Win_Trojan_Mybot_6249
{
strings:
	$a0 = { 334cb778d139001e42113449636d3bdfc1bb02ec55c3734a130138b83f2333032c9d4d6139bdde223dd5f96869db1f7163c9693c6bb77a4391f119f86483ef27e8b263b793c02b9225e15b2b1a0c9269337b9371490e0a4f0fdd2702d11f2ab79219f86214abd0ae883c66dc54a81a043583976d375c2df94d0929ac9091c1f89696c9ec91b92838709eedb6 }

condition:
	$a0
}

        