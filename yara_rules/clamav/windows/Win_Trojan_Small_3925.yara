rule Win_Trojan_Small_3925
{
strings:
	$a0 = { 6611bb30294902f47092a3f44b52afa3034c249cab92aba8e34cafa2ba860ca0585c3ae9d7887218ecd7fcd3e2929f2de5850cb4575eae19f49faeb9335eefa3334cc4eff48cafdc40453ad9af5eefa35752ae19dc4c85dd403923a9e2c29ba3ba4c248ce3233ae9d3ac }

condition:
	$a0
}

        
