rule Win_Trojan_Bancos_1300
{
strings:
	$a0 = { fcf4bcd3cae3ebd4315ffb3d4a3a50ecdeb4acf435d0d818919e1cd5d8d830bb176b24831277cd0097ec566d9e3773ffbec1f993a878c0e0c50dd40b9b755f2cc45e07cdb347ae4508e871d3ef80d36d7ca4e3fca377ba5ae3e3 }

condition:
	$a0
}

        
