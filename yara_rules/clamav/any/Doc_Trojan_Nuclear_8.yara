rule Doc_Trojan_Nuclear_8
{
strings:
	$a0 = { 28646c672e466f726d6174203d203029204f722028646c672e466f726d6174203d203129205468656e }
	$a1 = { 6442617369632e4d6163726f436f70792022476c6f62616c3a496e736572745061796c6f6164222c20576f726442617369632e5b57696e646f774e616d65245d2829202b20223a496e736572745061796c6f616422 }

condition:
	$a0 and $a1
}

        