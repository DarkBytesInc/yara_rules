rule Win_Spyware_Banker_1119
{
strings:
	$a0 = { 3ead62d440b9c79c7491965da0a1fd08c8df017d6805a3b7a59878e76ef96be53c2f61aa81416212c093c5f23d0e8621e0c8cf78ed1a327ae7fd2d8039a3c5a9b90b77ca99f7fa34c33f61e4b46880bd7e12e2d818515a745f1afa375e7dbb7fd5dc5b9e8cb76b5ce0f7a64801d12904f54b9589d0836d4e639f2e0a8cfd982775d1311a }

condition:
	$a0
}

        