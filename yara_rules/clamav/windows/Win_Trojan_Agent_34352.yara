rule Win_Trojan_Agent_34352
{
strings:
	$a0 = { 55577ccfb00ab5a8abc3ec1b65133972bf8d7728b0b4de6b882f60ecb6cf28ba89afedacfdab6ccf0a866a28a67ed4ec42bcb06987737f8eaac98ba935a09fde0701faf206fe7d15c8763ca587afc3fd16d61537206bcbc3c158dcd0ccc888298f190171b202965291d4de2214202d2b }

condition:
	$a0
}

        
