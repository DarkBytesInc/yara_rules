rule Win_Trojan_SdBot_2281
{
strings:
	$a0 = { 63e32adc39d3cca5034fd335a6eab10e0d8eacea9f27e26dd01a40c91dd7ae69a4fa1575c8a34f08db77a7f4652b1cb8fc34a1034ca9f354bf58ec0bcacbd3157094c55338b432df2b00d838c0c8fc81be4ffc69f46cb7ddab4e6b77388e3c0bb6884f }

condition:
	$a0
}

        
