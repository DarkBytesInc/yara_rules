rule Win_Spyware_Banker_5133
{
strings:
	$a0 = { fd81271001e8b7f6f6f3b19d9c8a8f83edeb01c00a03da98bcb0a8bfdd8ca5a3b05980115683fdcfc888a2a8ba11c5e0c33d2efd1a03e084b8bffed8c1d1d4d7c3b40b4300c62c54d72c66fde4ac58e2a4dde7fd26f8310088dce5fbec847efd662465807034101a1c00cb85b56aafd89326f6fd680c2cfbd255da9dd9 }

condition:
	$a0
}

        
