rule Win_Worm_Bagle_18
{
strings:
	$a0 = { 23d1034ac779fb613b38fc7138defeffffffc5c6c489e8c6ce89f0febbc6a188f5fefc11f1fe0611fdd6c43a1af8fed1500e3e0c1e72a901b22ec7477f375c1c5ec9712224c506a23305083df8e0c3547ae38ee345127ec7868ffd9be0ffe0bb }

condition:
	$a0
}

        
