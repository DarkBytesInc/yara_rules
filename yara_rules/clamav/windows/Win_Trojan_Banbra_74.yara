rule Win_Trojan_Banbra_74
{
strings:
	$a0 = { 3e1cbd489b6bdf33802a74a7604d10eb9182200b34193d18917bc071f27ac06f58f54385316e7201129bcb244faec2a7db1c96978bdcacee4f9c823729e9d97981b22538c013cb0309360ee8d721d9a91d468cf6215fb44ca7fe42aa7e9f3ec16a3105a4994c937f583c6a8cb63bb2545cb5e358e0b48882a8a338f8956760ba0f87dfe9fa59ae7a47e942eee4d18e95bc }

condition:
	$a0
}

        