rule Win_Trojan_AvatarAcid_1
{
strings:
	$a0 = { e800005d81ed0300b8ffa02bdbcd210681fbffa0745ab82135cd21899ea2028c86a4028cd8488ec026803e00005a757e26832e03002e9026832e12002e9026a1 }

condition:
	$a0
}

        
