rule Win_Downloader_Small_322
{
strings:
	$a0 = { 4df8516a046a0068003040008b55fc52ff15042040006a048d45f8506a046a0068103040008b4dfc51ff1504204000c745f400000000eb098b55f483c2018955f4837df41f73236a048d45f8506a046a008b4df46bc90581c118304000518b55fc52ff1504204000ebce6888130000ff150c2040006a006a0068f8304000681831400068243140006a00ff15 }

condition:
	$a0
}

        