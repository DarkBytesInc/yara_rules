rule Win_Trojan_SdBot_3743
{
strings:
	$a0 = { 6c4d828a6e2a302b633c06b1c3a937c48a4acbdc681240c5579d49025a9889ef0ba91fc0ecd22f06c907c69c13cf308048b4ba25eba841ed541d4afb70b9eec55374b4d2072f67d2848eb80fb9a13be637db64f9c694a5b2ccbaa0d52bcdeea2bf154faf9da29ac62578739e069d }

condition:
	$a0
}

        
