rule Win_Trojan_Vawtrak_2
{
strings:
	$a0 = { 8bf6e986f5ffffb868540010833d80350410008b2598350410750e2de80300008305803504103950 }

condition:
	$a0
}

        
