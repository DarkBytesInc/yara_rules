rule Win_Trojan_Crypt_330
{
strings:
	$a0 = { 0bd18bd30bf78bd00bf3ff1564405000b022ff156440500080e2be4ad3da2ad6f7db13c6d2fb80c730d3db02ced2e0b18f6800000000ff157c405000fec532f7e907feffffff3d00003d3d3dffff00ff0000003d003d003d003d00ff003d00ff3d003d3d3dff3dff00ff3d3d003d3d00ffff3d2acc0aeab3f30aeb8bce8bdeb2 }

condition:
	$a0
}

        
