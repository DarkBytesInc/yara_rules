rule Win_Trojan_IRC_Script_107
{
strings:
	$a0 = { 6c6f6164696e6720636c6f6e657320746f20243220242b203a20242b202433200d0a20207d0d0a7d0d0a616c696173 }

condition:
	$a0
}

        
