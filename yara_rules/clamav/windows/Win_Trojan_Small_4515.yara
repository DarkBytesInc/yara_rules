rule Win_Trojan_Small_4515
{
strings:
	$a0 = { 2e777269746528756e657363617065282725334325373325363325373225363925373025373425323025364325363125364525363725373525363125363725363525334425323225364125363125373625363125373325363325373225363925373025373425323225334525 }

condition:
	$a0
}

        