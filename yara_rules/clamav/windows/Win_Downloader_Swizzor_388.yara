rule Win_Downloader_Swizzor_388
{
strings:
	$a0 = { 670e6cb80403522289921bcce62ac0617d4147bfe8e8107a840480aaaf16d6e293101ed05a78b2df33fd85474ac07b5f64f7f114209627f565fcddab0f61af6e5368dabe409afe4f9d55b0231a5edce82d843a7041c8e880b0b4 }

condition:
	$a0
}

        
