rule Win_Trojan_Mybot_4959
{
strings:
	$a0 = { dc159a75bd28cc868e2de88650069f255aae4e39ddd5b91f52024da572c8abf75561b8ffd3ac4893a8d05217dd0b99c0939d3e8cf072b96ff369f63674192057edb9adb0a52415c144dfe786a69c }

condition:
	$a0
}

        
