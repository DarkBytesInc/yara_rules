rule Win_Trojan_Spambot_264
{
strings:
	$a0 = { f13a16c50acbabd51afffff001fdffadf3472ecda4c14e78f2aa64bb4bcf03ffffffff6fe17a7b82720f38f4e345331e972bf1682fface348cf6c77731af1e6807d6a34affffff77033bbbfcb2282d273a87019738161459d12f5353827c78fff12f7e1dadb68d2946eb4575f9c7 }

condition:
	$a0
}

        
