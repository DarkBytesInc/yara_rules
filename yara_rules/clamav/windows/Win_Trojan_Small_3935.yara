rule Win_Trojan_Small_3935
{
strings:
	$a0 = { 6af2b9b26adebd8a66d2bfb266deb13637da5eb6bdd350e702c6b97942d634f61297dc3e5fc6347586cabf06a9a7b53142d634f628c6639c42ac309c42accb09576624b6424dcc73bdb331a91c9b6f35c9db88e602c6629c42 }

condition:
	$a0
}

        
