rule Win_Trojan_SdBot_3684
{
strings:
	$a0 = { d7b7cdec9a47ca97592fe3906b89024544422ce72fc8074c3cd26b74d0d8ccb70212ad0b31be6ecf0616becda763f5719ad791bf0959e573d55ab0a51620fa501a63e220d69e78b30a0200a8b58b }

condition:
	$a0
}

        
