rule Win_Trojan_Agent_31829
{
strings:
	$a0 = { 735f40bc1f83c106b8107113ced64141f4527e0c7d6750f0a6a00d0b51fbf7ac9b661e08a40410206a0668f608874c76b6a1d497501e00f004093b338f511c60636f5234233d5024ef26541d5d2fe857c7856421885901ec5c3e34502472d028856c55c1b3aa00b9249bee6d9e4f70ff8d8d1854286828eda420ba4094082cfff650c48e9d244c83bd522076cf7d6b85412501028bfb }

condition:
	$a0
}

        