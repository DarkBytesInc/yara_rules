rule Win_Trojan_Agent_33233
{
strings:
	$a0 = { 72a754ad1e25ea4a1dca3c85515177eeefc03e124b66b23db579cfc398dcefe2f3f0e66485e779846dbce812a8116d40915211b269246c231598416192456601586125b4c8496cc8b5b30915308f84c91b57245ab811b0c9e1598f85b715bce5cee77f0effffffa7df7e1fdefdfaf5f3ef86e61a61987e1ebcfd0823ab76e1d1519e218452dedf71e8e6f8a9 }

condition:
	$a0
}

        