rule Win_Trojan_SdBot_3789
{
strings:
	$a0 = { eaea6868c5c5a6d7bb0b92f168536db0727e7ecbb810ea6868c5c5a6fdbb2092f168536db0727e7ecbb84fea6868c5c5a638bb5892f168536db0727e7ecbb877ea6868c5c5a656bb5092f168536db0727e7ecbb89cea6868c5c5906d8a707e7ea1e8 }

condition:
	$a0
}

        
