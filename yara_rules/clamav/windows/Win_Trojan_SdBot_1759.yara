rule Win_Trojan_SdBot_1759
{
strings:
	$a0 = { c95c664d573cd0ae32da5d15e5bcb22adaa40cd5571f8325ea6a24863aef6129890fe6642e849b9a6dc35489ef85e912020809874ee05b5ef02515da5a14ea032339581a98e41c119a3620222317e5982729292aa3a828c2d1cfce723bc770f78e40f4c18de5f4f4f32d8acf64264144 }

condition:
	$a0
}

        