rule Win_Downloader_Small_3432
{
strings:
	$a0 = { ab915021c588ff25ced67a52c706d7e619ba733c28207a8710763f4adcadb09409c71e7ba491c3341edd0f4966da0f71489b891e15223abf9be6832c78644212f7dc51446fa7f1ab68cdcc13bc97ba7eb5a9baf44b }

condition:
	$a0
}

        
