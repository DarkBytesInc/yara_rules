rule Win_Trojan_Mybot_5148
{
strings:
	$a0 = { bd058a1f947ec1627db6f801191cbc45a7b8483cab4ebb73d2cbceb4ddf3a399c542f94d9ebec4d4160b1f7d51cf8b8698404b057cdf460378abdf79d81eb2441896c4e0d6f406c9b71f5f8a74d63a1ebee54c6fc9dcd8c30f6ff5c4694498d93cb4b6d0292e00c293841e51eb40a1a6a2b1ca1cdfdbbb10f420c3c88a509df265f644a650a560aaae3b5a4f0f05e9518a0970253106 }

condition:
	$a0
}

        