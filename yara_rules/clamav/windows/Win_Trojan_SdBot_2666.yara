rule Win_Trojan_SdBot_2666
{
strings:
	$a0 = { 2c19c9a56f75a76f626ebd8d102a3d37e95e2feffa2ff7db97931ccd1df7cca0c5ff9b32ec22a8844e985c78f254cbd828f7786344705541d380c40cb4d7e61949f3f810e135facd9108c5a4cd04b452fb4748b5bbb5cc061c1b4776 }

condition:
	$a0
}

        
