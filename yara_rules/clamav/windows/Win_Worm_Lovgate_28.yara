rule Win_Worm_Lovgate_28
{
strings:
	$a0 = { bad803bf2c5ca6ea5bcd856cd39fec1d480a7a1bcead158efee92dd12a10c3b72e9d6249a633c804737d2f31ee75ccfc42f46cfbf1028316799a00a98c07a38f916f21caca64eb1bf1abcda9e8649e3b632c56862fa65364522afc8aed05a1f0508026e1ed18119787f699ccce95eaeba3dc0bbb8bb0d3c91d8aba1945 }

condition:
	$a0
}

        
