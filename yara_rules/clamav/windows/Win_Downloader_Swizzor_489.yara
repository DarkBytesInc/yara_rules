rule Win_Downloader_Swizzor_489
{
strings:
	$a0 = { f74b9f860db377513f7a5686d7ac0548d006df6f8dca313579ad921cd8862a9677fce4e497eef439b36a8cc7ba878ae8913180d274e4db861585a8ea9493f0ac8f6942b9d33718cf39df520162a9 }

condition:
	$a0
}

        
