rule Win_Trojan_Spambot_132
{
strings:
	$a0 = { ffffffff05ea024f0bbd30de3900e6b4badf8fc66b39fe91d3084a5b7a5726f28ea28a0fff3f0bf8cd57e4a66ab76bb28cfc5655a7d74dfd9fffffffffabe82f47215aa4e6bc58af54eedbb09a546e3acd1cd73636cf6e6fe58b6a7ba9ffffc1ff904d72faa59900c13e840f1b1a }

condition:
	$a0
}

        
