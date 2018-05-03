rule Unix_Tool_13380_1
{
strings:
	$a0 = { 6a6658996a015b52536a0289e1cd805b5dbe80fffffe66bd911ff7d6560fcd09dd55436a105150b06689e1cd80 }
	$a1 = { 89e1b004cd80b0036a015acd804185c075f483e906ffe1 }

condition:
	$a0 and $a1
}

        
