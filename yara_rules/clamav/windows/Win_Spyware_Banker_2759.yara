rule Win_Spyware_Banker_2759
{
strings:
	$a0 = { 615a3f1deb2877d7f61522e62fc15ee54d3b0fbcb982fb16ba70cb40ec13b64af55303b2b05f2bbe295e04b752927aa259457a933dd197d8de144eb9f9218cea5e2ba8e66a3571e62c3d27aba1a6ed02829a062e6ca6e59cbf4a89f9a065baf2c54fd88a }

condition:
	$a0
}

        
