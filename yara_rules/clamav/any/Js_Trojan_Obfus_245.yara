rule Js_Trojan_Obfus_245
{
strings:
	$a0 = { 7768696c6528732e6c656e6774683e69297b76763d652871712b225b695d22293b63633d772e66726f6d63686172636f6465287061727365696e742822222b7676292b3338293b632b3d63633b693d312b693b7d656528226528632922293b }

condition:
	$a0
}

        