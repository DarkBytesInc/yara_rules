rule Win_Trojan_Startpage_421
{
strings:
	$a0 = { c923833c32303130303034d85625bc17c7053218098940ab84b04561c1d3635f52837e28706c61796d049360231b105fbb9cdeda51724221636164f658aab02480635f5e1268119fbc446029c25b5742acb5824d2204 }

condition:
	$a0
}

        