rule Win_Trojan_Lmir_147
{
strings:
	$a0 = { 9a25c81cb350eadc42e8cb76d91b955fdb8807a31b12bdc46aaf3ebe12b578bc12b2a02b5f145dc8369a4fb7f3029ae06409b551f7d07460bfc2e3dfc6438b73224a1ebfc28ed546ed296a2e8b42cd7793a68176105c2be8671cd1eba26a2fb110aaa44713940e22a3fa692599b8fb270188f80795c5fa45 }

condition:
	$a0
}

        