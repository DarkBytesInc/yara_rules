rule Win_Trojan_Uniemv_2
{
strings:
	$a0 = { 81e1fa00000083e947d3ee0fb6c80bf20fb65424??0fb6c20fb6170fafc80fb64424??81f1e801000081e98625000033ca03f10fb6c833d2b81f000000f7f10fb65424??0fb6ca4733c1803f00 }

condition:
	$a0
}

        
