rule Win_Trojan_ExeStealth_1
{
strings:
	$a0 = { 504d3fd6d6f98f88d382daf0d1a0d3d47f5eadb623d72d8ff88820ddac6bc176d73a5f1ca2c5b6899f9edbeb54f9bdbba6ae5c642c42a237ba581b43b4475e61f61ce50d1486b95e5cd2a78930c497783a253a5754514643605d928f8c697e7bb8b5caa7a4a1d6d3f0ede1dedb100d }

condition:
	$a0
}

        
