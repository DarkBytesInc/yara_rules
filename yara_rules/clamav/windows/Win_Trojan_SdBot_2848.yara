rule Win_Trojan_SdBot_2848
{
strings:
	$a0 = { c122f4b20c4c5fcbfba1ba68c96e15e6c39e410bad879cee42c4b77ba1f8620477cfba2a1a019e91acaf05135f605c51bea2c80e94f05d28a1134a338489c44c7675b979abd7dd30bf20d8ed7b074fb835b5a9312477ff893e4038c07c8dc4600e9f03992dfbd9e8bc61be8c11acabec624b1621c546fc160b16c69c0e907c2e8de5a3c661c500075b6777921678848c735c3ac7b19d }

condition:
	$a0
}

        