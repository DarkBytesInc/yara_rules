rule Win_Trojan_Cannabis_4
{
strings:
	$a0 = { 3d01fe0e5c00782fba5501e8290032e4cd1624df3c597523b200b400cd137214bae601e81100b90100bb0102b8010399cd137307baf401b409cd21c3 }

condition:
	$a0
}

        
