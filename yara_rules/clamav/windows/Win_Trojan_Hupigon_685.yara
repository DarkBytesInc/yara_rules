rule Win_Trojan_Hupigon_685
{
strings:
	$a0 = { 1f81f1369b264f9c724ed065f78619d239d2892262ee013d23897952039ad1445b2f70f53b1c6bbab076dd3c57d57ecacf3e6b1f06c6e596bd98911990de226d19 }

condition:
	$a0
}

        
