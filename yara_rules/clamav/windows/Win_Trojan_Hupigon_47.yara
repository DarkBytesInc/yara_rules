rule Win_Trojan_Hupigon_47
{
strings:
	$a0 = { 397141ae2ad1465ed67033f58766217605d263292a577a1420b62f41bcc76c94885fcc04ded76519de960237b011c3cd295b260a1866e57937823b458e7a15da2cf1d74181c41e5038cf206081e5e221421c83dd1d0dd77657544544ccb214482cc2cb1b569d5fc348b7ae55b86753221224f03434fb6262624cc726421cb8d1df1b0ba710d6c2b2eee25429cb0f1d0cf7710a56bf80 }

condition:
	$a0
}

        