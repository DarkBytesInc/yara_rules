rule Win_Trojan_SdBot_1718
{
strings:
	$a0 = { 05963c6281d0d6df6490802c46234f5f9776f69a2638bb704633f25a5bac84e6862e19d42f3cb6057cd0989b2ba04a713443c35828f3659a2830ea4a307bf98ce684aa82072bb60e6640239efee785a328bef0a1d62c10235f9d1f88d30207256a62e537afe7a044c1036a51407b046a0e71fb714c241c6734 }

condition:
	$a0
}

        