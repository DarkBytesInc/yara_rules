rule Win_Trojan_SdBot_3503
{
strings:
	$a0 = { 00ca6336555df6d70ce1f833c8006888f17f412142831c27117cc04f393b200cac0000000000d44b17bc307a6ec9013a62cf9782b3faecce910ed6cb4af460ccbd0da51f000000000075772b2dc54f0ca90035b60633698de9af01eb1a873eeeae9ec0f55c07ccf4f6000000003f38f08f200fcb00a24648b4d1096a5600ee26b9eb7b6055cc00af8eb7ece8 }

condition:
	$a0
}

        