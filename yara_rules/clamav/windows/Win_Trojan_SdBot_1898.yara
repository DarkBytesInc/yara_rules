rule Win_Trojan_SdBot_1898
{
strings:
	$a0 = { ab1e2180efe659ecb3069a379e584ba9695ae5d6dba19736cdcd5aea2e95c9e75be4a99d081a51039c0885df64508cac8fb8f7d2ea4a99d9a4c5737526d5b8dbcaffb9293581e8244208903856886a908ca4fdfe0146a2f1bcccb075 }

condition:
	$a0
}

        
