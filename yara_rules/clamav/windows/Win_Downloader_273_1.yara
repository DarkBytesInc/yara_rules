rule Win_Downloader_273_1
{
strings:
	$a0 = { 07af53325d36ee10788068600d23d5dcab5c04a93b5035f81a83112129e114e4a1f87da09bb1de6a070ffbb7b5a55d26fbfcfea793f13bf6d5790f1fd39113fcb35646b90fdcf874962109a391bc }

condition:
	$a0
}

        
