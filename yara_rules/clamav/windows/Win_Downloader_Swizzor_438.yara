rule Win_Downloader_Swizzor_438
{
strings:
	$a0 = { c76321833a6b5473be6889fa5fae4b77f9357eadf4d835f77ab32269c038b96c385a24adf43e2fd41dfb5eaca6babd3365524a8ff0d7a05c1587ec2ecd7af6404ebec9b267ef070d55e8b5138241c60fd21f1e6222be398ef795 }

condition:
	$a0
}

        
