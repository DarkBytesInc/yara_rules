rule Win_Trojan_SdBot_3905
{
strings:
	$a0 = { 1cf2e341dd2974ab97dca2e144df16853b8092bbc13d49898efbeadf68f377e5434549fc74c04ded1a686af5e85ebd2214ecf1366dfd068007f24047f50ebcdb514aa05d4edf1359f25292d167f846b2a35e368b12fb849322bdce47 }

condition:
	$a0
}

        
