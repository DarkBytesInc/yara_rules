rule Win_Trojan_Spambot_208
{
strings:
	$a0 = { ba84b66f1ec9f33ea28f3a21704efc6d6d0bbf39a53becaaffff5fff7372c22807b6f203b3799eb01a1181e4bf1f1e098d50b5000afaf8ffff839811835d1283b56c19eaf7906bfe19fd68242ae2cf7bddffffffff6d2ce3035eb5b2c9c99c5a8e5631394cfa2b6f2ec9e418a811 }

condition:
	$a0
}

        
