rule Win_Trojan_Bifrose_63
{
strings:
	$a0 = { eabd0f5c93d7f5381c21920712242a98a86069ab1d9d7fa6626d20fc4948a2a046a3fc31808228514002312442218fc54a6c3084121ed3769bddb7fdce6eedb49b9bddea3a6da9da0aea145bd7dad655ac6e4b8b6b63a1952a35ef39f7791282daedbbcffb7e3eeffb7e7e5fea7d9e7bcfbdf7dc73cf39f7dc73ff3ce9 }

condition:
	$a0
}

        
