rule Win_Downloader_Banload_645
{
strings:
	$a0 = { b83f5c815499ef0270594deca60f59ec24ed1e4191603d8f2dbabdcfa038e2b1d8d60bc41494793618fb9e6868daeff76264d60d9af95c7b5f63fe66bc92c01da7321b797740d1c4c8dd706bb203af7fa98e090c314447da652a8bf2a8d6cdac6b778ca600f28e51602b6ed2bd47de93fa9056f860e0 }

condition:
	$a0
}

        