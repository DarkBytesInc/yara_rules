rule Win_Trojan_Keyman_1
{
strings:
	$a0 = { 4a18596e5c52358813e2e4ea19abd742a1a4e3ba7b03753c54c0dbd9291db854ea55c411321fb429d5427950e0a9ed3a92c99c0dcc8b79ace9440757c81b46aca9483d3fc4a84ed7826a0156c05d68484826a4e7249b0da7215e9cfe6755344dc95d51135258e72519b819c012bc24c44fc8932d4fb0f1ccf24659230c3528267b9c2964a059a4893d04377b247164903e48eb652040 }

condition:
	$a0
}

        