rule Win_Trojan_Hupigon_719
{
strings:
	$a0 = { e558736ed6bdeadbdb347759efbe074ba4dd2465f069213cdbee935090599d8f1d76e66d2cc885a16c50da017cee0dabd0a3d5e3f0c046c25a4756ea7da679614bf82c8533b2efd2ae88dcbc3c4151cfb05b870f98583303 }

condition:
	$a0
}

        
