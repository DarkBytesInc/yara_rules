rule Win_Downloader_300_1
{
strings:
	$a0 = { ffc0ffafa870ca6c9a6b8440383e3160361ef4a410a490ef94b0603e05ce043585e8dddfe8ed777876fafc6db097727af3991c9a716ceb7321ed1c2aa918e483b464ec91391a36c090ee13920f478b2d16eba9ce619391e1ef0d }

condition:
	$a0
}

        
