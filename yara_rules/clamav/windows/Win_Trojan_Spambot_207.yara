rule Win_Trojan_Spambot_207
{
strings:
	$a0 = { d62cdf6ed1bd40480330486ddb28558d53b7e9ef767e72860c33143ffcffffb4d0bc71d666c4d09412194d99cf57b0ca6efaeda080ebeccdcee3ff0fffe62a94f2a35e7652db29296957c5725737aa6a3e3eff42ffff13236bef34a189ee6d0c1fb77f6a68cf68a3af70669aff1f }

condition:
	$a0
}

        
