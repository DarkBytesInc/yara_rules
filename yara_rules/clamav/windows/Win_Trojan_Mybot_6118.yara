rule Win_Trojan_Mybot_6118
{
strings:
	$a0 = { a087ba6483edf5d60d4fcb89d22f8b22c80ff2f45996740d713e4268e964eb1640c9c219e75ebb23d54bacb04f310bf16b6447b4d4281b0fde0c8c9b4befe7f6718d4169ca881ebe9e0029bd868292c533b4539cb348e6eeaed82aa9dc0edcf5ec1f28d11af36e3e10bfebf0373ff6ca46c4fd30520ace28 }

condition:
	$a0
}

        
