rule Html_Phishing_Pay_129
{
strings:
	$a0 = { 6c696d69746564206163636f756e74206163636573732064657461696c73[0-150]646561722070617970616c206d656d6265722c[0-150]776520726567756c61726c792073637265656e20616374697669747920696e207468652070617970616c2073797374656d2e20616674657220726576696577696e6720796f7572 }

condition:
	$a0
}

        