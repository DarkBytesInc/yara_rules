rule Win_Trojan_SdBot_3907
{
strings:
	$a0 = { 8fac094ddf3ebe09d8bbe92029e7062a0397661ff77c35a97c18a378c44768b1497631cd83be78e2d5d00d02f7e1b37d6eeb2666af3c3441d33becb3c27566dd9b0c57635ed63c6ed7b142536a5d2d3d338f388d734d165d03892642 }

condition:
	$a0
}

        