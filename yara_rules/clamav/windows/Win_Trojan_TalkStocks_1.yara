rule Win_Trojan_TalkStocks_1
{
strings:
	$a0 = { 626c617a6566696e642e636f6d2f6279652f6d735f757064617465732e7068703f6c616e673d0000713500002671353d00000000713400002671343d000000006e6f74617661696c61626c65 }

condition:
	$a0
}

        