rule Win_Downloader_Agent_32351
{
strings:
	$a0 = { 440ee60841942a99b3016c99ededa140e8cdb3068967234e4a0fb27121f27425ebd823c901dc7b8f5e3cb2c01872c1bbdcf9e8ac661bd108aecd5ec85f7b5bccc55c49b364c09f5b67b15b64133acdbb17141c006dcf66705cb533d5e4b6bd228a05d17b8c33273b196c48a6485aeee35ab60d12b7a31cff49f5a193f863ec75e85f8b0451cb2655499df1d8c16eb7b252fce91a }

condition:
	$a0
}

        