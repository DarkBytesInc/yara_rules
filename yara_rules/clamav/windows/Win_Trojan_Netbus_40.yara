rule Win_Trojan_Netbus_40
{
strings:
	$a0 = { 974a76eb0204a7410b00bc377cc38815b9a7d5b4e14cca5753926ed9c9537f97dd4c6816a390ade22113191b95db05d06e0aecac68206cbd50eaeb3ea64f328aab556db3d2b5f1cbbf1c90c1045df7683af4f631406a56a6fc3af164a7344de6732b5b6a }

condition:
	$a0
}

        
