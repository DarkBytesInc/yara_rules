rule Win_Trojan_SdBot_4510
{
strings:
	$a0 = { bdf77aefb7f5ae77dddea00e7fae06fc531fbe5ba7abdcb5c65ea46bd979b6205ea72b5fedcc7dbfc2bf2e3b23923eabbb50977bfc75d5a0d3f59d53664fc3a7ebd4d545ba5dd96317eb227f56e66503a2846dfd728a5bbfdebfe07447912e54ea3a82281591775c7be8b92b93e2bee3 }

condition:
	$a0
}

        
