rule Win_Downloader_Time2Pay_11
{
strings:
	$a0 = { 6c8b56fe9836f9644d69c874685cd8687b65c6646869fcb1f0f3558a7d28a25684f229c8f03f6a32dffe04f6de45de14710898ac1c7b557e654eb83ade7e415e53cfff8ae58d46bd0a42fc8c4abf76b7f0c0fd32d45c235cf5caa3ba0cc16dcf629a6164c0cf7a8cde8e78d2c27a6773b60b7ebbdab47cd624d46f }

condition:
	$a0
}

        
