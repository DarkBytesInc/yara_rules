rule Win_Downloader_Banload_1938
{
strings:
	$a0 = { 599817560d023569748ade830b57d4586dc8378864656e9dda240a77c819da0a33cacd8f8d75f1dd5179356953c4a13744a955f378cb3ea52181c2dab74fa2422aef139d924da85d }

condition:
	$a0
}

        
