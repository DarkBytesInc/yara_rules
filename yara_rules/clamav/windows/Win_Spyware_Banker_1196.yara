rule Win_Spyware_Banker_1196
{
strings:
	$a0 = { 97c2cfcd18f9f7a78bd74c3d13efd562e9c0c15d9eb9d525bec58a9546c3e090bb43bbf8751bb2a3e7c31736443c5e65341cd8d37dfeab8b26965f9cfffc96dc46c394e86221c7f68d8e3bb2e1f37913cfe52a3dabc6cc0a0517 }

condition:
	$a0
}

        
