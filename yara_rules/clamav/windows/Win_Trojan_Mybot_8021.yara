rule Win_Trojan_Mybot_8021
{
strings:
	$a0 = { c3fd0d4beb65a8b3149559ea72fb003ba6ebfd5d61782935d5b66b7e4f740af0dc7e8b29dc5c721cdb5fbeca060c5d249b01d50b1b6d2d2dd7400df2ad0c4ac90a0950a1516adb3c2a08aba050f38b7a067373c4b0a40a4e5a06f2eae7ac956507ab331a1979acf073a9e14df0f912f9adcc2554c8a8942ffd0f49f95e913fcd98a4ce9c67225146980e }

condition:
	$a0
}

        