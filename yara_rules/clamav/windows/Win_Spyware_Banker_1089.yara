rule Win_Spyware_Banker_1089
{
strings:
	$a0 = { df9489c126cbb71a2cb10a0db84a2aff72a814d4a1e3aa095ead7b62304abf06108aea44d391fe49a4049209eb6c7e59eb1505a9e9c85c3823052b1a6afc684c53e68bd15abe2f7e7b0541f373c30d6f96b3c13fd14dff069fd8cd2b33714e0ec16d6b6cb0818fbe06b7aa5b113b5bbb24fc4aeda3a2ee48b7e230f68001052feb1c4222f5c8089c52c25fc550bf457b }

condition:
	$a0
}

        