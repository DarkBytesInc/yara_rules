rule Win_Downloader_47_2
{
strings:
	$a0 = { 57b18e4bd99d7c8b48a546e8296d96c4250b78fdcab14e83fce2760fc12141f319d548189c6f3a65477d27a3fd4f846cb13109cdc00b06be11cf911dbb187e82e52facaf475987547eb6d5af8b5c90d1460a05fd27aa8ad814bb }

condition:
	$a0
}

        
