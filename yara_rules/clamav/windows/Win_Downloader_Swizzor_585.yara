rule Win_Downloader_Swizzor_585
{
strings:
	$a0 = { b68220149d8cce9b8e9f242de5e489de308efa39de3ea98f1a0007b88adb4c64e49ef9d976bdb35430ebfda0a446773726dca6c971faea5298807b31b93398b04f7c1cf5b5da9f1ee958bdea0f691226528d5de6b1fb94a5a61d5c50bf4aaac10bc5ef9941a3205c6c }

condition:
	$a0
}

        
