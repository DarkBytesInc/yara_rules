rule Win_Downloader_Swizzor_426
{
strings:
	$a0 = { 37bdaf21655069b8f4c427463b566b879767e8208e0711cfa528417ee735e8c91a7bfafd9e90f9dce94b2c6853cb5bf29da033c569f00e5e8cfe29eb611d391a1cd900b2f5e6a86435dc93ece40b6ccfaac0ff537762671d4834 }

condition:
	$a0
}

        
