rule Win_Trojan_SdBot_1707
{
strings:
	$a0 = { 513a4f72549aadcdb11e08f280a3c35212d919c306bd70ae1a14ffe5bf2759b23cb4d19651e496e3f25b5cddc8c56222c79fa38dcd9104f98fb9567a2f94e81b6406bc4d3584c2d468bedef079d5a202c5f177671ddf51d86352f8e3ce620307698cf811958c57a70f52406c74c7 }

condition:
	$a0
}

        