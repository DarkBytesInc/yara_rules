rule Win_Spyware_Banker_5835
{
strings:
	$a0 = { 5615aa16055b0917bb4671588fad56d26d986f5846d244ec22426c81c61b6d2cf644c03508167cd94ca3f0eaf39a518e9f8031f40758df85b47648bb5c7d9f77b5999e50740c06a59aedbfb1ae08754bdfe323aa0bd9ee15ea9dda69731b4fcb89a8a63a631b210da175b95400b63ed011d7b80786775fc6994149ebc8874d3c }

condition:
	$a0
}

        